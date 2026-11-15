from fastapi import FastAPI, Depends, Response, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from routers import scan
from database import get_db

import os

app = FastAPI(
    title="PhishLens XAI API",
    description="Explainable multi-engine phishing detection platform",
    version="1.0.0"
)

allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "https://phishlens-doyc.onrender.com",
]
if os.getenv("ALLOWED_ORIGIN"):
    allowed_origins.append(os.getenv("ALLOWED_ORIGIN"))

# CORS — allow the Vite React dev server, Render frontend, and Chrome extension to reach the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins + ["chrome-extension://*"],
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Include routers
app.include_router(scan.router)

# Serve built frontend static files if present (allows Render to serve full Web Dashboard)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir) and os.path.exists(os.path.join(static_dir, "index.html")):
    app.mount("/assets", StaticFiles(directory=os.path.join(static_dir, "assets")), name="assets")

    @app.get("/")
    async def serve_spa_root():
        return FileResponse(os.path.join(static_dir, "index.html"))

    @app.get("/favicon.svg")
    async def serve_favicon():
        return FileResponse(os.path.join(static_dir, "favicon.svg"))

    @app.get("/favicon.ico")
    async def serve_favicon_ico():
        return FileResponse(os.path.join(static_dir, "favicon.svg"))

    @app.get("/icons.svg")
    async def serve_icons():
        return FileResponse(os.path.join(static_dir, "icons.svg"))

    @app.get("/api")
    def read_root():
        return {"message": "Welcome to the PhishLens XAI API"}
else:
    @app.get("/")
    def read_root():
        return {"message": "Welcome to the PhishLens XAI API"}

@app.get("/health/db")
def health_db(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return JSONResponse(status_code=200, content={"status": "ok"})
    except Exception:
        return Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


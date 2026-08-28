from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import scan

app = FastAPI(
    title="PhishLens XAI API",
    description="Explainable multi-engine phishing detection platform",
    version="1.0.0"
)

# CORS — allow the Vite React dev server to reach the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the PhishLens XAI API"}

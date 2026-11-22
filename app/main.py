import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.database import init_db
from app.auth import hash_password
from app.database import bootstrap_admin
from app.services.scheduler import start_scheduler, stop_scheduler

app = FastAPI(
    title="Website Security & Certificate Analyzer",
    description="Live TLS, DNS and HTTP posture analysis with evidence, mitigation and scan history.",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3001,http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API router
app.include_router(router)


from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request data"}
    )

@app.on_event("startup")
def on_startup():
    init_db()
    admin_user = os.getenv("BOOTSTRAP_ADMIN_USERNAME")
    admin_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
    if admin_user and admin_password:
        bootstrap_admin(admin_user, hash_password(admin_password))
    start_scheduler()


@app.on_event("shutdown")
def on_shutdown():
    stop_scheduler()

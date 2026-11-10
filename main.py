import os

import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from supabase import AuthApiError, AuthError, Client, create_client

# ---------------------------------------------------------------------------
# Stage 0: load secrets from .env and create the Supabase client
# ---------------------------------------------------------------------------
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
PORT = int(os.getenv("PORT", "8000"))

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_URL / SUPABASE_KEY are not set. Copy .env.example to .env and fill it in."
    )


def get_supabase() -> Client:
    """Return a fresh Supabase client.

    signUp / signInWithPassword store the session inside the client object.
    If one client were shared by every request, users could end up sharing
    session state, so each auth call gets its own client.
    """
    return create_client(SUPABASE_URL, SUPABASE_KEY)


# One client at startup to prove the URL/key are well-formed.
get_supabase()
print("Server running and connected to Supabase")

app = FastAPI(
    title="Auth Login & Protect API",
    description="Sign up, log in, log out and protected routes using Supabase Auth.",
    version="1.0",
)


# ---------------------------------------------------------------------------
# Errors: always answer with {"error": "..."} like the assignment asks
# ---------------------------------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": "Invalid request body"})


# ---------------------------------------------------------------------------
# Stage 1: sign up & log in
# ---------------------------------------------------------------------------
class Credentials(BaseModel):
    # Defaults of "" so a missing field becomes our own 400, not FastAPI's 422.
    email: str = ""
    password: str = ""


def require_credentials(body: Credentials) -> None:
    if not body.email.strip() or not body.password.strip():
        raise HTTPException(status_code=400, detail="Email and password are required")


@app.post("/auth/signup", status_code=201, tags=["Auth"])
def signup(body: Credentials):
    require_credentials(body)
    try:
        result = get_supabase().auth.sign_up(
            {"email": body.email, "password": body.password}
        )
    except AuthError as e:
        raise HTTPException(status_code=400, detail=e.message)
    return result.user.model_dump(mode="json")


@app.post("/auth/login", tags=["Auth"])
def login(body: Credentials):
    require_credentials(body)
    try:
        result = get_supabase().auth.sign_in_with_password(
            {"email": body.email, "password": body.password}
        )
    except AuthApiError:
        raise HTTPException(status_code=401, detail="Invalid login credentials")
    return {
        "access_token": result.session.access_token,
        "refresh_token": result.session.refresh_token,
    }


# ---------------------------------------------------------------------------
# Stage 2: public route
# ---------------------------------------------------------------------------
@app.get("/public/info", tags=["Public"])
def public_info():
    return {"message": "Welcome stranger! This info is public."}


# ---------------------------------------------------------------------------
# Stage 3-5: the guard (a reusable dependency). HTTPBearer also makes the
# "Authorize" padlock appear in Swagger UI.
# ---------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=False)  # auto_error=False -> we choose the error


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    """Verify the bearer token with Supabase and return the user.

    Missing / badly formatted header -> 401 "Access token required"
    Expired, tampered or invalid token -> 401 "Invalid or expired token"
    """
    if credentials is None or not credentials.credentials.strip():
        raise HTTPException(status_code=401, detail="Access token required")

    token = credentials.credentials.strip()
    try:
        response = get_supabase().auth.get_user(token)
    except AuthError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if response is None or response.user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Keep the token around so /auth/logout can revoke this exact session.
    response.user._token = token
    return response.user


@app.get("/protected/profile", tags=["Protected"])
def profile(user=Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat()
        if hasattr(user.created_at, "isoformat")
        else user.created_at,
    }


@app.get("/protected/dashboard", tags=["Protected"])
def dashboard(user=Depends(get_current_user)):
    return {"message": f"Welcome to your dashboard, {user.email}!"}


# ---------------------------------------------------------------------------
# Stage 4: logout (protected by the same dependency)
# ---------------------------------------------------------------------------
@app.post("/auth/logout", status_code=204, tags=["Auth"])
def logout(user=Depends(get_current_user)):
    try:
        # Revokes the session that belongs to this user's access token.
        get_supabase().auth.admin.sign_out(user._token)
    except AuthError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return Response(status_code=204)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)

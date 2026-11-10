# Auth Login & Protect API

A small FastAPI backend that handles **sign up, log in and log out** with **Supabase Auth** and protects routes by verifying the user's JWT on every request. Passwords and tokens are managed by Supabase (the Identity Provider), not by this server.

## Setup

1. Create a free project at [supabase.com](https://supabase.com) and copy the **Project URL** and **anon key** from *Project Settings -> API*.
2. For quick testing, you can turn off *Confirm email* under *Authentication -> Providers -> Email*; otherwise confirm the email before logging in.
3. Install and configure:
   ```
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env     # then fill in SUPABASE_URL and SUPABASE_KEY
   ```

`.env` is git-ignored. Never commit your keys.

## Run

```
python main.py
```

You should see `Server running and connected to Supabase`. The API runs on `http://localhost:8000` (change `PORT` in `.env`). Swagger UI is at `http://localhost:8000/docs`.

## API reference

| Method | Path | Auth required | Description | Success |
|--------|------|---------------|-------------|---------|
| POST | `/auth/signup` | No | Create an account (`email`, `password`) | 201 |
| POST | `/auth/login` | No | Returns `access_token` and `refresh_token` | 200 |
| POST | `/auth/logout` | Yes (Bearer) | Ends the session | 204 |
| GET | `/public/info` | No | Public message | 200 |
| GET | `/protected/profile` | Yes (Bearer) | User id, email, created_at | 200 |
| GET | `/protected/dashboard` | Yes (Bearer) | Second protected route | 200 |

Errors: `400` missing email/password, `401` wrong credentials or missing/invalid/expired token. All errors look like `{"error": "..."}`.

## Try it with curl

```
curl -i -X POST http://localhost:8000/auth/signup -H "Content-Type: application/json" -d '{"email":"test@example.com","password":"password123"}'
curl -i -X POST http://localhost:8000/auth/login  -H "Content-Type: application/json" -d '{"email":"test@example.com","password":"password123"}'
curl -i http://localhost:8000/protected/profile -H "Authorization: Bearer <access_token>"
```

## How the guard works

`get_current_user` is a FastAPI dependency. It reads the `Authorization: Bearer <token>` header, calls `supabase.auth.get_user(token)`, and returns 401 if the token is missing, malformed, expired or tampered with. Every protected route (including logout) just declares `user = Depends(get_current_user)`, so the route body only runs for verified users. A fresh Supabase client is created per auth call so sessions are never shared between users.

## Swagger UI

![Swagger UI](docs/swagger-ui.png)

*(Add your screenshot of `/docs` showing the lock icons here.)*

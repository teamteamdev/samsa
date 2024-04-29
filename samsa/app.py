from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware import Middleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi_async_sqlalchemy import SQLAlchemyMiddleware, db
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import text

from samsa.models import Base
from samsa.routes.account import router as account_router
from samsa.routes.profile import router as profile_router
from samsa.routes.sso import router as sso_router
from samsa.settings import settings
from samsa.templates import templates


@asynccontextmanager
async def lifespan(_: FastAPI):
    async with db():
        await db.session.execute(text("""CREATE EXTENSION IF NOT EXISTS "uuid-ossp";"""))
        conn = await db.session.connection()
        await conn.run_sync(Base.metadata.create_all)
        await db.session.commit()
    yield


app = FastAPI(
    debug=settings.debug,
    docs_url=None, redoc_url=None, openapi_url=None,
    lifespan=lifespan,
    middleware=[
        Middleware(
            SQLAlchemyMiddleware,
            db_url=settings.database_url,
            commit_on_exit=True,
            engine_args={
                "echo": settings.debug,
                "pool_pre_ping": True,
                "pool_size": 8,
                "max_overflow": 8
            }
        )
    ]
)
app.include_router(sso_router, prefix="/.sso")
app.include_router(account_router, prefix="/sso")
app.include_router(profile_router, prefix="")
app.mount("/.sso/static", StaticFiles(directory="static"))


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={"error": str(exc.detail)},
            status_code=exc.status_code
        )
    else:
        return JSONResponse(
            content={"error": str(exc.detail)},
            status_code=exc.status_code
        )

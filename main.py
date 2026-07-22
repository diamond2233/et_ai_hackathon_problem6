"""SentinelAI API — application entry point.

    uvicorn app.main:app --reload --port 8000

Interactive docs at /docs, ReDoc at /redoc, OpenAPI JSON at /api/v1/openapi.json.
"""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import analytics, analyze, auth, chat, complaints, reports
from app.core.config import settings
from app.core.database import close_mongo_connection, connect_to_mongo, mongo
from app.services.llm import get_llm
from app.services.similarity import matcher

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinelai")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown.

    The campaign matcher is fitted here, once, rather than per request. It costs
    ~40 ms at boot and turns every subsequent similarity lookup into a single
    sparse matrix multiply.
    """
    logger.info("Starting %s v%s (%s)", settings.APP_NAME, settings.APP_VERSION,
                settings.ENVIRONMENT)

    await connect_to_mongo()

    started = time.perf_counter()
    extra = []
    if mongo.connected and mongo.db is not None:
        # Fold any corpus messages already in the database into the matcher, so
        # newly reported campaigns become detectable without a redeploy.
        try:
            cursor = mongo.db.scam_corpus.find(
                {"is_scam": True}, {"_id": 0, "text": 1, "scam_type": 1, "message_id": 1}
            ).limit(2000)
            async for doc in cursor:
                extra.append({
                    "id": doc.get("message_id", "CORPUS"),
                    "name": f"Reported campaign ({doc.get('scam_type', 'unknown')})",
                    "threat": doc.get("scam_type", "unknown"),
                    "text": doc.get("text", ""),
                    "first_seen": "corpus",
                })
        except Exception as exc:
            logger.warning("Could not load corpus into matcher: %s", exc)

    matcher.build(extra_corpus=extra)
    logger.info("Campaign matcher ready: %d fingerprints in %.0f ms",
                matcher.size, (time.perf_counter() - started) * 1000)

    if get_llm() is not None:
        logger.info("Gemini reasoning layer active (%s)", settings.GEMINI_MODEL)
    else:
        logger.warning("Gemini inactive — running deterministic-only. "
                       "Detection still works; explanations use templates.")

    yield

    await close_mongo_connection()
    logger.info("Shutdown complete")


app = FastAPI(
    title="SentinelAI API",
    description=(
        "AI-powered fraud and digital-arrest-scam detection for Indian citizens.\n\n"
        "**Detect. Explain. Protect.**\n\n"
        "The detection pipeline fuses four layers: a deterministic rule engine, "
        "TF-IDF campaign fingerprinting, structural signal analysis, and a Gemini "
        "reasoning pass via LangChain. The first three run locally in single-digit "
        "milliseconds, so the service degrades gracefully rather than failing when "
        "the LLM is unavailable."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    contact={"name": "SentinelAI", "url": "https://github.com/your-team/sentinelai"},
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Process-Time"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def add_process_time(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time"] = f"{elapsed:.1f}ms"
    if elapsed > 3000:
        logger.warning("Slow request %s %s took %.0f ms",
                       request.method, request.url.path, elapsed)
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    """Turn Pydantic's nested errors into something a frontend can show a user."""
    problems = []
    for err in exc.errors():
        field = " → ".join(str(p) for p in err["loc"] if p != "body")
        problems.append({"field": field or "request", "message": err["msg"]})
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Some fields need attention", "problems": problems},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Something went wrong on our side. Please try again."},
    )


# ------------------------------------------------------------------- routes

for r in (auth.router, analyze.router, chat.router, analytics.router,
          complaints.router, reports.router):
    app.include_router(r, prefix=settings.API_PREFIX)


@app.get("/", tags=["Meta"], summary="Service banner")
async def root():
    return {
        "name": settings.APP_NAME,
        "tagline": "Detect. Explain. Protect.",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["Meta"], summary="Health and dependency status")
async def health():
    """Reports which subsystems are live.

    `degraded` is a deliberate state, not a failure: with Gemini down the
    detection engine still runs at full deterministic accuracy.
    """
    db_ok = mongo.connected
    llm_ok = get_llm() is not None

    if db_ok and llm_ok:
        state = "healthy"
    elif db_ok:
        state = "degraded"
    else:
        state = "unhealthy"

    return {
        "status": state,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "components": {
            "database": "connected" if db_ok else "unreachable",
            "gemini": "active" if llm_ok else "inactive (deterministic mode)",
            "campaign_matcher": f"{matcher.size} fingerprints" if matcher.ready else "not built",
        },
        "detection_available": True,
    }

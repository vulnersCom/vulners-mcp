from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from app.server import mcp

async def health(_):
    return PlainTextResponse("ok")

# Put /health BEFORE the catch-all Mount("/")
app = Starlette(
    routes=[
        Route("/health", health),
        Mount("/", app=mcp.streamable_http_app()),
    ]
)


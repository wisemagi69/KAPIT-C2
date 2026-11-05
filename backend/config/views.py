"""Serve only the compiled website; never expose the repository or originals."""
import mimetypes
from pathlib import Path

from django.conf import settings
from django.http import FileResponse, JsonResponse

from .errors import not_found


def built_file(relative):
    root = Path(settings.WEB_DIST_DIR).resolve()
    candidate = root / relative
    # Do not follow a junction/symlink outside the reviewed build tree.
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def website(request):
    if request.method not in {"GET", "HEAD"}:
        return JsonResponse({"code": "METHOD_NOT_ALLOWED", "message": "This method is unavailable."}, status=405)
    index = built_file("index.html")
    if index is None:
        return JsonResponse({"code": "WEB_BUILD_REQUIRED", "message": "Build the local website before opening it."}, status=503)
    return FileResponse(index.open("rb"), content_type="text/html; charset=utf-8")


def asset(request, filename):
    if request.method not in {"GET", "HEAD"}:
        return JsonResponse({"code": "METHOD_NOT_ALLOWED", "message": "This method is unavailable."}, status=405)
    # Vite's hashed assets have one filename; directories and dotfiles are denied.
    if "/" in filename or "\\" in filename or filename.startswith("."):
        return not_found(request)
    file = built_file("assets/" + filename)
    if file is None or file.suffix.lower() not in {".js", ".css", ".woff", ".woff2", ".png", ".svg", ".jpg", ".webp"}:
        return not_found(request)
    return FileResponse(file.open("rb"), content_type=mimetypes.guess_type(file.name)[0] or "application/octet-stream")

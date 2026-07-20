from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
import tempfile
import os
import json
import uuid

from main import LogAnalyzerAI

router = APIRouter()

_analysis_sessions: dict = {}


# -----------------------------
# Test APIs
# -----------------------------
@router.get("/")
async def root():
    return {
        "success": True,
        "message": "🚀 Log Analyzer API is running successfully!"
    }


@router.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "Log Analyzer API"
    }


@router.get("/ping")
async def ping():
    return {
        "message": "pong"
    }


# -----------------------------
# Upload & Analyze API
# -----------------------------
@router.post("/analyze")
async def analyze_logs(file: UploadFile = File(...)):
    """
    Step 1: Parse + enrich + classify IPs.
    Returns a session_id used later for executive report streaming.
    """

    extension = os.path.splitext(file.filename)[1].lower()
    allowed = [".csv", ".xlsx", ".xls"]

    if extension not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Only CSV, XLSX and XLS files are supported."
        )

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=extension
    ) as temp_file:

        temp_file.write(await file.read())
        temp_path = temp_file.name

    try:
        analyzer = LogAnalyzerAI(temp_path)

        ip_results = analyzer.run_ip_analysis()

        session_id = str(uuid.uuid4())

        _analysis_sessions[session_id] = {
            "analyzer": analyzer,
            "ip_results": ip_results,
            "temp_path": temp_path,
        }

        return {
            "success": True,
            "session_id": session_id,
            "count": len(ip_results),
            "ip": ip_results,
        }

    except Exception as e:

        if os.path.exists(temp_path):
            os.remove(temp_path)

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# -----------------------------
# Executive Report Streaming API
# -----------------------------
@router.get("/analyze/{session_id}/executive-report/stream")
async def stream_executive_report(session_id: str):

    session = _analysis_sessions.get(session_id)

    if not session:
        raise HTTPException(
            status_code=404,
            detail="Session not found."
        )

    analyzer = session["analyzer"]
    ip_results = session["ip_results"]
    temp_path = session["temp_path"]

    def event_generator():

        full_text = ""

        try:

            for token in analyzer.stream_executive_report(ip_results):

                full_text += token

                yield (
                    f"data: {json.dumps({'type': 'token', 'content': token})}\n\n"
                )

            try:

                report = json.loads(full_text)

                yield (
                    f"data: {json.dumps({'type': 'done', 'report': report})}\n\n"
                )

            except json.JSONDecodeError:

                yield (
                    f"data: {json.dumps({'type': 'done', 'raw': full_text, 'parse_error': True})}\n\n"
                )

        except Exception as e:

            yield (
                f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
            )

        finally:

            _analysis_sessions.pop(session_id, None)

            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception as ex:
                    print(f"Failed to delete temp file: {ex}")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
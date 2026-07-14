# from fastapi import APIRouter, UploadFile, File
# import tempfile
# import os

# from main import LogAnalyzerAI

# router = APIRouter()


# @router.post("/analyze")
# async def analyze_logs(file: UploadFile = File(...)):

#     # Save uploaded file temporarily
#     with tempfile.NamedTemporaryFile(
#         delete=False,
#         suffix=".csv"
#     ) as temp_file:

#         content = await file.read()
#         temp_file.write(content)

#         temp_path = temp_file.name

#     try:
#         analyzer = LogAnalyzerAI(temp_path)

#         analysis = analyzer.run()
#         return {
#             "success": True,
#             "count": len(analysis),
#             "ip": analysis
#         }

#     except Exception as e:
#         return {
#             "success": False,
#             "error": str(e)
#         }

#     finally:
#         if os.path.exists(temp_path):
#             os.remove(temp_path)
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
import tempfile
import os
import json
import uuid

from main import LogAnalyzerAI

router = APIRouter()

# In-memory store mapping a session id -> LogAnalyzerAI instance + ip results.
# Swap this for Redis/DB in production; a single-process dict is fine for dev.
_analysis_sessions: dict = {}


@router.post("/analyze")
async def analyze_logs(file: UploadFile = File(...)):
    """
    Step 1: Parse + enrich + classify IPs (fast, synchronous).
    Returns the IP threat-intel results plus a session_id used to
    kick off the streamed executive AI report next.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_file:
        content = await file.read()
        temp_file.write(content)
        temp_path = temp_file.name

    try:
        analyzer = LogAnalyzerAI(temp_path)
        ip_results = analyzer.run_ip_analysis()

        session_id = str(uuid.uuid4())
        _analysis_sessions[session_id] = {
            "analyzer": analyzer,
            "ip_results": ip_results,
        }

        return {
            "success": True,
            "session_id": session_id,
            "count": len(ip_results),
            "ip": ip_results,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@router.get("/analyze/{session_id}/executive-report/stream")
async def stream_executive_report(session_id: str):
    """
    Step 2: Streams the AI-generated executive SOC report as Server-Sent
    Events. Each event carries a raw text token; the frontend concatenates
    them to build up the JSON (and can render partial text live).
    A final 'event: done' message signals completion, with the parsed
    JSON if it parsed cleanly.
    """
    session = _analysis_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or already expired")

    analyzer: LogAnalyzerAI = session["analyzer"]
    ip_results = session["ip_results"]

    def event_generator():
        full_text = ""
        try:
            for token in analyzer.stream_executive_report(ip_results):
                full_text += token
                # SSE format: each message is "data: <payload>\n\n"
                payload = json.dumps({"type": "token", "content": token})
                yield f"data: {payload}\n\n"

            # Try to parse the full accumulated text as JSON for a clean final payload
            try:
                parsed = json.loads(full_text)
                done_payload = json.dumps({"type": "done", "report": parsed})
            except json.JSONDecodeError:
                done_payload = json.dumps({
                    "type": "done",
                    "report": None,
                    "raw": full_text,
                    "parse_error": True,
                })

            yield f"data: {done_payload}\n\n"

        except Exception as e:
            error_payload = json.dumps({"type": "error", "message": str(e)})
            yield f"data: {error_payload}\n\n"

        finally:
            # Clean up the session once streaming is done
            _analysis_sessions.pop(session_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering if applicable
        },
    )
# from fastapi import APIRouter, UploadFile, File, HTTPException
# from fastapi.responses import StreamingResponse
# import tempfile
# import os
# import json
# import uuid

# from main import LogAnalyzerAI

# router = APIRouter()

# # In-memory store mapping a session id -> LogAnalyzerAI instance + ip results.
# # Swap this for Redis/DB in production; a single-process dict is fine for dev.
# _analysis_sessions: dict = {}


# @router.post("/analyze")
# async def analyze_logs(file: UploadFile = File(...)):
#     """
#     Step 1: Parse + enrich + classify IPs (fast, synchronous).
#     Returns the IP threat-intel results plus a session_id used to
#     kick off the streamed executive AI report next.
#     """
#     extension = os.path.splitext(file.filename)[1].lower()

#     allowed = [".csv", ".xlsx", ".xls"]

#     if extension not in allowed:
#         raise HTTPException(
#         status_code=400,
#         detail="Only CSV and Excel files are supported."
#         )

#     with tempfile.NamedTemporaryFile(
#         delete=False,
#         suffix=extension
#     ) as temp_file:
#         content = await file.read()
#         temp_file.write(content)
#         temp_path = temp_file.name

#     try:
#         analyzer = LogAnalyzerAI(temp_path)
#         ip_results = analyzer.run_ip_analysis()

#         session_id = str(uuid.uuid4())
#         _analysis_sessions[session_id] = {
#             "analyzer": analyzer,
#             "ip_results": ip_results,
#         }

#         return {
#             "success": True,
#             "session_id": session_id,
#             "count": len(ip_results),
#             "ip": ip_results,
#         }

#     except Exception as e:
#         return {
#             "success": False,
#             "error": str(e),
#         }

#     finally:
#         if os.path.exists(temp_path):
#             os.remove(temp_path)


# @router.get("/analyze/{session_id}/executive-report/stream")
# async def stream_executive_report(session_id: str):
#     """
#     Step 2: Streams the AI-generated executive SOC report as Server-Sent
#     Events. Each event carries a raw text token; the frontend concatenates
#     them to build up the JSON (and can render partial text live).
#     A final 'event: done' message signals completion, with the parsed
#     JSON if it parsed cleanly.
#     """
#     session = _analysis_sessions.get(session_id)
#     if not session:
#         raise HTTPException(status_code=404, detail="Session not found or already expired")

#     analyzer: LogAnalyzerAI = session["analyzer"]
#     ip_results = session["ip_results"]

#     def event_generator():
#         full_text = ""
#         try:
#             for token in analyzer.stream_executive_report(ip_results):
#                 full_text += token
#                 # SSE format: each message is "data: <payload>\n\n"
#                 payload = json.dumps({"type": "token", "content": token})
#                 yield f"data: {payload}\n\n"

#             # Try to parse the full accumulated text as JSON for a clean final payload
#             try:
#                 parsed = json.loads(full_text)
#                 done_payload = json.dumps({"type": "done", "report": parsed})
#             except json.JSONDecodeError:
#                 done_payload = json.dumps({
#                     "type": "done",
#                     "report": None,
#                     "raw": full_text,
#                     "parse_error": True,
#                 })

#             yield f"data: {done_payload}\n\n"

#         except Exception as e:
#             error_payload = json.dumps({"type": "error", "message": str(e)})
#             yield f"data: {error_payload}\n\n"

#         finally:
#             # Clean up the session once streaming is done
#             _analysis_sessions.pop(session_id, None)

#     return StreamingResponse(
#         event_generator(),
#         media_type="text/event-stream",
#         headers={
#             "Cache-Control": "no-cache",
#             "Connection": "keep-alive",
#             "X-Accel-Buffering": "no",  # disable nginx buffering if applicable
#         },
#     )
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
import tempfile
import os
import json
import uuid

from main import LogAnalyzerAI

router = APIRouter()

_analysis_sessions: dict = {}


@router.post("/analyze")
async def analyze_logs(file: UploadFile = File(...)):
    """
    Step 1: Parse + enrich + classify IPs.
    Returns a session_id used later for executive report streaming.
    """

    # Validate extension
    extension = os.path.splitext(file.filename)[1].lower()

    allowed = [".csv", ".xlsx", ".xls"]

    if extension not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Only CSV, XLSX and XLS files are supported."
        )

    # Save uploaded file
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

        # Store everything required for the next request
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

        # Delete temp file if analysis fails
        if os.path.exists(temp_path):
            os.remove(temp_path)

        return {
            "success": False,
            "error": str(e),
        }


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
                    f"data: {json.dumps({'type':'token','content':token})}\n\n"
                )

            try:

                report = json.loads(full_text)

                yield (
                    f"data: {json.dumps({'type':'done','report':report})}\n\n"
                )

            except json.JSONDecodeError:

                yield (
                    f"data: {json.dumps({'type':'done','raw':full_text,'parse_error':True})}\n\n"
                )

        except Exception as e:

            yield (
                f"data: {json.dumps({'type':'error','message':str(e)})}\n\n"
            )

        finally:

            # Remove session
            _analysis_sessions.pop(session_id, None)

            # Delete temporary uploaded file
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
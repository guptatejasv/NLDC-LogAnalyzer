from fastapi import APIRouter, UploadFile, File
import tempfile
import os

from main import LogAnalyzerAI

router = APIRouter()


@router.post("/analyze")
async def analyze_logs(file: UploadFile = File(...)):

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".csv"
    ) as temp_file:

        content = await file.read()
        temp_file.write(content)

        temp_path = temp_file.name

    try:
        analyzer = LogAnalyzerAI(temp_path)

        analysis = analyzer.run()
        return {
            "success": True,
            "count": len(analysis),
            "ip": analysis
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
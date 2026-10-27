"""
AVÉRION - Hugging Face Spaces Entry Point
Serves the full FastAPI backend + Gradio wrapper on port 7860.
"""
import sys
import os

# Ensure project root is on the path so `backend.main` resolves
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gradio as gr
from backend.main import app as fastapi_app

# ---- Gradio Blocks (minimal landing that redirects to the real dashboard) ----
with gr.Blocks(title="AVÉRION – AI Document Verification", theme=gr.themes.Base()) as demo:
    gr.Markdown(
        """
        # 🛡️ AVÉRION – AI Document Verification Platform
        ### Smart India Hackathon 2026 • SIH26261

        **[➡️ Open Full Dashboard](./)**

        This Space serves a full-stack FastAPI + EasyOCR forensic document
        verification engine with:
        - Cross-Document Intelligence
        - Explainable AI (XAI)
        - Multi-Factor AI Risk Scoring
        - Adaptive Regulatory Compliance
        - Privacy-First PII Redaction

        Click the link above to access the complete dark-mode dashboard.
        """
    )

# Mount Gradio on /gradio path; FastAPI handles everything else (/, /api/*)
app = gr.mount_gradio_app(fastapi_app, demo, path="/gradio")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)

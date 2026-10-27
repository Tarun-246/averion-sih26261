import os
import gradio as gr
from backend.main import app as fastapi_app

# Mount Gradio and FastAPI together
# Root "/" serves our dark-mode HTML dashboard
# "/api/*" serves all forensic & OCR endpoints
# "/gradio" provides standard Gradio fallback
demo = gr.mount_gradio_app(fastapi_app, gr.Blocks(title="AVÉRION - SIH26261"), path="/gradio")

# Export app for ASGI servers like uvicorn on Hugging Face
app = fastapi_app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(fastapi_app, host="0.0.0.0", port=7860)

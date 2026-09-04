# Prahari — border-outpost appliance image.
#
# CPU-only by default so it runs on whatever hardware an outpost actually
# has. For the GPU build, swap the base for an NVIDIA CUDA runtime image
# and install ultralytics + TensorRT; see README.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OPENCV_FFMPEG_CAPTURE_OPTIONS="rtsp_transport;tcp" \
    TZ=Asia/Kolkata

# ffmpeg for decode and evidence clips; libGL for OpenCV
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg libgl1 libglib2.0-0 curl tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY prahari/ ./prahari/
COPY config/ ./config/
COPY scripts/ ./scripts/

RUN mkdir -p /data/evidence /app/media

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["uvicorn", "prahari.server.app:app", "--host", "0.0.0.0", "--port", "8000"]

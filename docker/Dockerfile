FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    wget \
    curl \
    gnupg \
    libnss3 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libx11-xcb1 \
    libdrm2 \
    libxdamage1 \
    libxcomposite1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libxshmfence1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -m playwright install chromium

EXPOSE 8000

CMD ["uvicorn","backend.app:app","--host","0.0.0.0","--port","8000"]

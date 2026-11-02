# Optional: lets the backend run on any cloud that runs containers (AWS, Azure, Google Cloud, Render...).
# Render's free plan does not need this file (it can build Python directly), but it keeps the project portable.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Most platforms inject PORT; default to 8000 for local runs.
ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]

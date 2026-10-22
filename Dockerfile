FROM python:3.13-slim
WORKDIR /app
COPY bugbark ./bugbark
ENV PYTHONUNBUFFERED=1 BUGBARK_CONFIG=/app/config.toml BUGBARK_DATA=/app/data
CMD ["python", "-m", "bugbark"]

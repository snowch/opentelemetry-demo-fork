FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.4.1.tgz \
    | tar xz --strip-components=1 -C /usr/local/bin docker/docker

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .
COPY ddl.sql .
COPY templates/ templates/

EXPOSE 5000

CMD ["python", "web_ui.py"]

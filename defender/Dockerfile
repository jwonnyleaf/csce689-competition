FROM python:3.12.2-slim as builder

WORKDIR /build

COPY docker-requirements.txt .

RUN pip install --no-cache-dir -r docker-requirements.txt

FROM python:3.12.2-slim

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

COPY . /app

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "defender.server:app"]

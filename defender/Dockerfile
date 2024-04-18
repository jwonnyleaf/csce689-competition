# Using Python 3.6.4 slim as a base image
FROM python:3.6.4-slim as builder

# Set the working directory
WORKDIR /build

COPY docker-requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r docker-requirements.txt

RUN apt-get update && apt-get install -y \
    git

RUN pip install git+https://github.com/elastic/ember.git

FROM python:3.6.4-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . /app

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "defender.server:app"]

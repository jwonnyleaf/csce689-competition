# Using Python 3.6.4 slim as a base image
FROM python:3.6.4-slim as builder

# Set the working directory
WORKDIR /build

# Install Docker Requirement
RUN pip install -r docker-requirements.txt

# Install TensorFlow
RUN pip install /tmp/tensorflow_wheel/tensorflow-*.whl

FROM python:3.6.4-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . /app

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "defender.server:app"]

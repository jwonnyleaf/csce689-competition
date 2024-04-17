# Using Python 3.6.4 slim as a base image
FROM python:3.6.4-slim as builder

# Set the working directory
WORKDIR /build

RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list \
    && sed -i 's/security.debian.org/debian-security.archive.debian.org/g' /etc/apt/sources.list

RUN apt-get update && apt-get install -y --allow-unauthenticated \
    gcc \
    g++ \
    libgomp1 \
    git \
    gnupg \
    wget \
    curl \
    unzip \
    libssl-dev \
    pkg-config \
    zip \
    zlib1g-dev

# Install Bazel with retry logic for more reliable download
RUN curl -LO --retry 5 --retry-delay 5 --retry-max-time 30 "https://github.com/bazelbuild/bazel/releases/download/3.7.2/bazel-3.7.2-installer-linux-x86_64.sh" \
    && chmod +x bazel-3.7.2-installer-linux-x86_64.sh \
    && ./bazel-3.7.2-installer-linux-x86_64.sh
ENV PATH="/root/bin:${PATH}"

RUN bazel version

RUN pip install --upgrade pip \
    && pip install numpy wheel
    
# Clone TensorFlow repository and checkout the compatible version
RUN git clone https://github.com/tensorflow/tensorflow.git /tensorflow

RUN git clone https://gitlab.com/libeigen/eigen.git /eigen
WORKDIR /eigen
ARG EIGEN_COMMIT=f612df273689a19d25b45ca4f8269463207c4fee
RUN git checkout ${EIGEN_COMMIT}

WORKDIR /tensorflow
RUN git checkout v2.5.0

# Configure TensorFlow build
RUN ./configure

# Build TensorFlow
RUN bazel build //tensorflow/tools/pip_package:build_pip_package

# Create the pip package and install
RUN ./bazel-bin/tensorflow/tools/pip_package/build_pip_package /tmp/tensorflow_pkg
RUN pip install /tmp/tensorflow_pkg/tensorflow-*.whl
FROM python:3.6.4-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . /app

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "defender.server:app"]

# Base image using Micromamba for managing Python dependencies
FROM mambaorg/micromamba:0.25.1 as ember

# Set working directory
WORKDIR /ember

# Install dependencies
COPY requirements_conda.txt .
RUN micromamba install -y -n base --channel conda-forge --file requirements_conda.txt && \
    micromamba clean --all --yes
ARG MAMBA_DOCKERFILE_ACTIVATE=1
# Copy all EMBER files
COPY --chown=$MAMBA_USER:$MAMBA_USER ./ember_lib /ember

# Install EMBER
RUN python setup.py install

# Base image for the final stage
# FROM python:3.6.15-slim-buster
# 3.8.19-bullseye
# Set the working directory

WORKDIR /app

COPY docker-requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r docker-requirements.txt

# Copy installed packages from Ember stage
# COPY --from=ember /opt/conda /opt/conda
# COPY --from=ember /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
# COPY --from=ember /usr/local/bin /usr/local/bin
# Ensure the environment is activated
# ENV PATH /opt/conda/bin:$PATH

# Copy other necessary binaries and files
# COPY --from=ember /usr/local/bin /usr/local/bin

# Copy the application files
COPY . .

EXPOSE 8080

CMD ["/opt/conda/bin/python", "-m", "gunicorn", "-b", "0.0.0.0:8080", "defender.server:app"]

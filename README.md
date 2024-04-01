
# CSCE 689

This project is developed as part of the coursework for CSCE689: ML-Based Cyber Defenses. It represents a practical application of machine learning techniques in the domain of cybersecurity, aiming to identify, analyze, and defend against cyber threats using data-driven approaches.


## Prerequisites
Before you begin, ensure you have the following installed:

* Python (version 3.6 or newer)
* Docker
* Conda (optional, but recommended for managing Python environments)


## Installation

### Clone the Repository
First, clone the project repository to your local machine:

```bash
  git clone hhttps://github.com/jwonnyleaf/csce689-competition.git
  cd defender
```

### Setup Virtual Environment
You can skip this step if you're using Docker to run the project.

If using `conda` (recommended):
```bash
conda create --name defender-app python=3.12.2
conda activate defender-app
```
Or using Python's built in `venv`:
```bash
python -m venv venv
source venv/bin/activate
```

### Install Dependencies
Install the required Python packages:
```bash
pip install -r docker-requirements.txt
```

### Running the Application with Docker
To containerize the application and run it using Docker
1. Build the Docker image
    ```bash
    docker build -t defender.app .
    ```
2. Run the Docker container
    ```bash
    docker run -itp 8080:8080 ml-cyber-defense
    ```
    The -p 8080:8080 flag maps port 8080 of the container to port 8080 on your host, allowing you to access the application via http://localhost:8080.

3. Verify the Docker/Installation
    ```bash
    curl http://localhost:8080/hello
    ```
You should receive a "Hello, World!" response if everything is set up correctly.


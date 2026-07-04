FROM python:3.8.13

# install OS security updates (fixes CVE-2025-27363 and other OS-level CVEs)
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install pip dependencies
RUN pip install 'matplotlib>=3.3,<3.4' \
                'psutil>=5.8,<5.9' \
                'tqdm>=4.59,<4.60' \
                'pandas>=1.1,<1.2' \
                'scipy>=1.5,<1.6' \
                'numpy>=1.10,<1.20' \
                'ipykernel~=6.0' \
                'azureml-core' \
                'azureml-defaults' \
                'azureml-mlflow' \
                'azureml-telemetry' \
                'scikit-learn==1.2.2'


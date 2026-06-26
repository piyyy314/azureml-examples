#FROM mcr.microsoft.com/azureml/openmpi4.1.0-ubuntu20.04
FROM python:3.8

# install OS security updates (fixes CVE-2025-27363 and other OS-level CVEs)
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# python installs
COPY requirements.txt .
RUN pip install -r requirements.txt && rm requirements.txt

# set command
CMD ["bash"]

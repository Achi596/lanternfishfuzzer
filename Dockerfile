FROM ubuntu:22.04

# Copy Python files into the container
COPY fuzzer_entry.py .
COPY fuzzer.py .
COPY fuzzer_harness.py .
COPY mutator_factory.py .
COPY plaintext_mutator.py .
COPY xml_mutator.py .
COPY mutator.py .
COPY json_mutator.py .
COPY csv_mutator.py .
COPY code_coverage.py .

# Install necessary dependencies
RUN apt-get update && \
    apt-get install -y gcc-10 g++-10 python3 python3-pip qemu-user && \
    rm -rf /var/lib/apt/lists/* 

# Install required Python packages
RUN pip3 install frida frida-tools

# Set the environment variable to ensure Python output is not buffered
ENV PYTHONUNBUFFERED=1

# Set the entry point to run the fuzzer entry script
CMD ["python3", "fuzzer_entry.py"]

# What is FaaSr
FaaSr is a serverless middleware that abstracts heterogeneous serverless workflow deployment as directed, acyclic execution graphs. With FaaSr, the idiosyncrasies of different serverless platforms are made transparent, making it easy to scale or migrate workflows without refactoring. Additionally, because workflows are not limited to a single platform, functions can be deployed to the platforms best suited to execute them. Importantly, FaaSr preserves the serverless abstraction by not relying on any centralized server.

At the moment, FaaSr supports **GitHub Action**, **AWS Lambda**, **GCP Serverless**, **OpenWhisk**, and **SLURM**, and functions can be written in **Python**, **R**, or **Julia** (soon). No changes to code are needed to incorporate a function into a FaaSr workflow, unless the user wishes to use the FaaSr S3 API for persistent storage. 

Each workflow function is executed inside of a FaaSr container on the user's platform of choice. Workflows leverage S3 for persistent data-storage, with a built-in API for performing I/O within user functions.
This package provides backend tooling for DAG validation, compute server/data store checks, user package installation, function fetching and execution, workflow orchestration, and structured S3 logging. 

See [here](https://faasr.io/) for the complete documentation.

# Using
To use FaaSr, you simply need to create a workflow JSON (see below) and host your functions on GitHub. Then, you can register, invoke, and set triggers for your workflows using FaaSr's UI.

# Workflow builder
The GUI for creating a workflow can be found here: [FaaSr-JSON-Builder](https://faasr.io/FaaSr-workflow-builder/)

# Prebuilt containers
### GitHub Actions
```
ghcr.io/faasr/github-actions-python:latest (Python)
ghcr.io/faasr/github-actions-r:latest (R)
```
### OpenWhisk
```
faasr/openwhisk-python:latest (Python)
faasr/openwhisk-r:latest (R)
```
### Google Cloud
```
faasr/gcp-python:latest (Python)
faasr/gcp-r:latest (R)
```
### Slurm
```
faasr/slurm-python:latest (Python)
faasr/slurm-r:latest (R)
```
### Kubernetes
```
faasr/kubernets-python:dev (Python)
faasr/kubernetes-r:dev (R)
```
### AWS Lambda
```
Email cutlern [at] oregonstate.edu or build your own
```

See [FaaSr-Docker](https://github.com/FaaSr/FaaSr-Docker) for building your own containers


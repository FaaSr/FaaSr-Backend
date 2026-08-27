import os

from setuptools import find_packages, setup

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

# The release workflow sets PACKAGE_VERSION from the version it was run with.
version = os.environ.get("PACKAGE_VERSION", "0.1.13")

setup(
    name="FaaSr_py",
    version=version,
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
)

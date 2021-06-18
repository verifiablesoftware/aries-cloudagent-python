# Hyperledger Aries Cloud Agent - Python For VSW  <!-- omit in toc -->

This is the replicated aca-py project for vsw to address the special requirement.
Basically it's the same as the aca-py code, until now there are only two minor changes below.
1. add accept-taa parameter
2. register public did and verkey in the sovrin.

## Table of Contents <!-- omit in toc -->

- [How to package](#how-to-package-aries-cloudagent-python)
- [How to upload to pypi](#how-to-upload-to-pypiorg)

## How to package aries-cloudagent-python?

upgrade version number in the file below.

`aries_cloudagent_vsw/version.py`

cd project root directory, then execute the following command.

`python setup.py sdist bdist_wheel`

## How to upload to pypi.org
For production: 

`twine upload dist/*`

For test: 

`twine upload --repository testpypi dist/*`
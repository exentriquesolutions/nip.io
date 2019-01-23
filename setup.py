# from distutils.core import setup
from setuptools import setup

setup(name="nip.io",
      version="1.0",
      packages=["nipio"],
      tests_require=["mock", "assertpy"],
      test_suite="nipio_tests",
      )

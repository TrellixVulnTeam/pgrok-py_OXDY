from setuptools import setup, find_packages

with open("README.md") as f:
    long_description = f.read()


setup(
    name="pgrok",
    version="0.1.0",
    entry_points={"console_scripts": ["pgrokpy=pgrok.pgrok:main"]},
    description="Python client for interacting with Pgrok!",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Sandip Dey",
    include_package_data=True,
    packages=["pgrok"],
    author_email="sandip.dey1988@yahoo.com",
    keywords=['ssh-tunnell', 'unix-tools', ''],
    url="https://github.com/sandyz1000/pgrok-py",
    license="Apache License",
    install_requires=["PyYAML"],
    platforms=["linux", "unix"],
    python_requires=">=3.5",
)

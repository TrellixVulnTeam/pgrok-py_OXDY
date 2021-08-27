from setuptools import setup, find_packages


if __name__ == "__main__":
    setup(
        name="pgrok-py",
        entry_points={"console_scripts": ["pgrokpy=pgrok.pgrok:main"]},
        version="0.1.0",
        description="Python client for interacting with Pgrok!",
        long_description=open("README.md").read(),
        long_description_content_type="text/markdown",
        author="Sandip Dey",
        author_email="sandip.dey1988@yahoo.com",
        url="https://github.com/sandyz1000/pgrok-py",
        license="Apache License",
        packages=find_packages(include=['pgrok']),
        include_package_data=True,
        install_requires=["psutils", "PyYAML"],
        platforms=["linux", "unix"],
        python_requires=">3.5.2",
    )

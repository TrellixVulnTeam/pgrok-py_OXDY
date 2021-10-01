from distutils.core import setup


setup(
    name="pgrok",
    packages=["pgrok"],
    include_package_data=True,
    install_requires=["PyYAML"],
    python_requires=">=3.5",
    entry_points={"console_scripts": ["pgrokpy=pgrok.pgrok:main"]},
    version="0.1.0",
    description="Python client for interacting with Pgrok!",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Sandip Dey",
    author_email="sandip.dey1988@yahoo.com",
    keywords=['ssh-tunnell', 'unix-tools', ''],
    url="https://github.com/sandyz1000/pgrok-py",
    license="Apache License",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: Apache License',
        'Programming Language :: Python :: 3.7+',
    ],
)

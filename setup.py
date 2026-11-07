from setuptools import setup, find_packages

setup(
    name="netpulse-cli",
    version="1.1.0",
    description="Ferramenta CLI para diagnóstico de redes, descoberta de hosts e análise de qualidade de link",
    author="NetPulse",
    author_email="contato@netpulse.dev",
    url="https://github.com/seu-usuario/NetPulse-CLI",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "icmplib>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "netpulse=netpulse.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
    ],
)

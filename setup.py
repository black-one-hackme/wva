from setuptools import setup, find_packages

setup(
    name='wva',
    version='1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'WVA = wva:main',
        ],
    },
    install_requires=[
        # List any dependencies here. For this script, none are required beyond standard library.
    ],
    author='Your Name',
    description='Web Vulnerabilities Analyzer (WVA)',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
    ],
)

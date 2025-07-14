from setuptools import setup

setup(
    name='reflix',
    version='1.0.0',
    py_modules=['reflix'],
    install_requires=[
        'colorama',
        'requests',
        'pyfiglet',
        'yaspin',
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'reflix = reflix:main',
        ],
    },
)

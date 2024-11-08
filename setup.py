from setuptools import setup, find_packages

setup(
    name="events",
    version="1",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": ["events = events:main"]
        },
    install_requires=[
        'Flask==2.1.1',
        'Flask-WTF==0.15.1',
        'icalendar==6.0.1',
        'humanize==3.12.0',
        'pytest==6.2.5',
        'tzlocal==2.1',
        'ecdsa==0.16.1',
        'requests>=2.24.0',
        'Werkzeug==2.0.2'
        ]
    )

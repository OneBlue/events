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
        'Flask==1.1.2',
        'Flask-WTF==0.15.1',
        'icalendar==4.0.1',
        'humanize==3.12.0',
        'pytest==6.2.5',
        'tzlocal==2.1',
        'ecdsa==0.16.1'
        ]
    )

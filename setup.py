from setuptools import setup, find_packages

setup(
    name="corsripper",
    version="1.0.0",
    description="CORS exploitation and impact analysis engine",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="kamalx06",
    url="https://github.com/kamalx06/CorsRipper",
    license="GPL-3.0-only",
    python_requires=">=3.9",
    packages=find_packages(),
    py_modules=["corsripper"],
    install_requires=[
        "requests",
        "requests[socks]",
        "playwright>=1.40; extra == 'browser'"
    ],
    entry_points={
        "console_scripts": [
            "corsripper=corsripper:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)

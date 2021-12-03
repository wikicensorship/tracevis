
from setuptools import setup, find_packages
from util._version import __version__

setup(
    name="tracevis",
    version= __version__,
    packages=find_packages(),
    scripts=["tracevis.py"],
    install_requires=['scapy', 'pyvis'],

    classifiers=[
        "Topic :: System :: Networking",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
    ],

    author="WikiCensorship",
    author_email="xhdix@yahoo.com",
    description="Traceroute with any packet. Visualize the routes. Discover Middleboxes and Firewalls",
    long_description="""
TraceVis is a research project whose main goal is to find middleboxes. Where 
a packet is tampered with or blocked. This tool also has other features such 
as downloading and visualizing traceroute data from RIPE Atlas probes.
""",
    license="The Unlicense",
    keywords="visualization dns packets network graphs packet ripe traceroute measurements censorship ripe-atlas ripe-ncc packet-tracer traceview middlebox firewall censorship",
    url="https://github.com/wikicensorship/tracevis",
)

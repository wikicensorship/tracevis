# TraceVis
Traceroute with any packet. Visualize the routes. Discover Middleboxes and Firewalls

[![CodeQL](https://github.com/wikicensorship/tracevis/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/wikicensorship/tracevis/actions/workflows/codeql-analysis.yml)
[![Dockerise](https://github.com/wikicensorship/tracevis/actions/workflows/docker.yml/badge.svg)](https://github.com/wikicensorship/tracevis/actions/workflows/docker.yml)
[![unittest](https://github.com/wikicensorship/tracevis/actions/workflows/unittest.yml/badge.svg)](https://github.com/wikicensorship/tracevis/actions/workflows/unittest.yml)


TraceVis is a research project whose main goal is to find middleboxes. Where a packet is tampered with or blocked. This tool also has other features such as downloading and visualizing traceroute data from RIPE Atlas probes.


![example graph](https://user-images.githubusercontent.com/12384263/159377323-1e4e594e-aca8-4f91-8174-0ba58f6a6454.png)

## Install and build

#### Note:
You need to install [npcap](https://npcap.com/) in **Windows**. If you already have programs like Wireshark or Nmap/Zenmap, they will install this automatically. 

(**Not** required on **Linux**.)

### Using ducker:
##### Pull docker image from github container registry:

```sh
docker pull ghcr.io/wikicensorship/tracevis
```

##### Or clone project and build docker image on your machine:

```sh
docker build -t tracevis .
```

### Directly:
##### Download or clone project and then install Python dependencies:

```sh
python3 -m pip install -r requirements.txt
```

## How to use

##### Default DNS trace:

```sh
python3 ./tracevis.py --dns
```

or with docker image:

```sh
docker run ghcr.io/wikicensorship/tracevis --dns
```

or trace in paris mode:

```sh
python3 ./tracevis.py --dns --paris
```

##### Packet trace:

```sh
python3 ./tracevis.py --packet
```

or with docker image:

```sh
docker run -it ghcr.io/wikicensorship/tracevis --packet
```

##### trace with a config file:

```sh
python3 ./tracevis.py --config ./samples/quicv0xbabababa.conf
```

or you can override:

```
python3 ./tracevis.py --config ./samples/syn.conf -i "75.2.60.5,99.83.231.61"
```

_(There is more in `./samples`: Client-Hello, NTP, HTTP-GET, and more QUIC packets)_

##### Download traceroute data from a RIPE Atlas probe:

```sh
python3 ./tracevis.py --ripe [probe-id]
```

or with docker image:

```sh  
docker run \
    --mount type=bind,source=/path/to/results,target=/tracevis_data/ \
    ghcr.io/wikicensorship/tracevis --ripe [probe-id]
# OR
docker run \
    -v /path/to/results/:/tracevis_data/ \
    ghcr.io/wikicensorship/tracevis --ripe [probe-id]

```

##### Visualize a json file:

```sh
python3 ./tracevis.py --file ./path/to/file.json
```

or with docker image:

```sh
docker run \
    --mount type=bind,source=/path/to/results,target=/tracevis_data/ \
    ghcr.io/wikicensorship/tracevis --file /tracevis_data/file.json
# OR
docker run \
    -v /path/to/results/:/tracevis_data/ \
    ghcr.io/wikicensorship/tracevis --file /tracevis_data/file.json

```

##### See the help message: 

```sh
python3 ./tracevis.py -h
```

or with docker image:

```sh
docker run ghcr.io/wikicensorship/tracevis
```

##

#### Examples:

![example graph](https://user-images.githubusercontent.com/12384263/144353391-b7add54f-ef8b-48e0-988f-8c64b95dca76.png)

![example cli](https://user-images.githubusercontent.com/12384263/137825581-e2bd4bdb-874f-4fad-9a54-6c39beab0398.png)

![example cli](https://user-images.githubusercontent.com/12384263/137825216-e76ddeaa-0592-422b-a08b-bd44329a6934.png)

![example cli](https://user-images.githubusercontent.com/12384263/144353450-4c6fd048-4353-482c-9571-523ad68eda30.png)

![example graph](https://user-images.githubusercontent.com/12384263/137825263-b5bc658e-a5af-47e3-9839-d1c75fa6be1b.png)

![example graph](https://user-images.githubusercontent.com/12384263/144697205-471b83a1-b98b-4b9f-8860-d8649a3d3e90.png)

![example graph](https://user-images.githubusercontent.com/12384263/144353412-37214aaa-040d-4b1f-a4b5-b812b96b1521.png)



# tracevis
Traceroute with any packet. Visualize the routes. Discover Middleboxes and Firewalls

traceroute is a research project whose main goal is to find middleboxes. Where a packet is tampered with or blocked. This tool also has other features such as downloading and visualizing traceroute data from RIPE Atlas probes.

## 

##### Install Python dependencies:

```sh
python3 -m pip install -r requirements.txt
```

##### Default DNS trace:

```sh
python3 ./tracevis.py --dns
```

##### Packet trace:

```sh
python3 ./tracevis.py --packet
```

##### Download traceroute data from a RIPE Atlas probe:

```sh
python3 ./tracevis.py --ripe [probe-id]
```

##### Visualize a json file:

```sh
python3 ./tracevis.py --file ./path/to/file.json
```

##### See the help message: 

```sh
python3 ./tracevis.py -h
```
##

#### Examples:

![example graph](https://user-images.githubusercontent.com/12384263/144353391-b7add54f-ef8b-48e0-988f-8c64b95dca76.png)

![example cli](https://user-images.githubusercontent.com/12384263/137825581-e2bd4bdb-874f-4fad-9a54-6c39beab0398.png)

![example cli](https://user-images.githubusercontent.com/12384263/137825216-e76ddeaa-0592-422b-a08b-bd44329a6934.png)

![example cli](https://user-images.githubusercontent.com/12384263/144353450-4c6fd048-4353-482c-9571-523ad68eda30.png)

![example graph](https://user-images.githubusercontent.com/12384263/137825263-b5bc658e-a5af-47e3-9839-d1c75fa6be1b.png)

![example graph](https://user-images.githubusercontent.com/12384263/144353412-37214aaa-040d-4b1f-a4b5-b812b96b1521.png)



## FetchNut

FetchNut is a Python-based network traffic analyzer using the Scapy library to capture and analyze network packets. The script identifies different protocols and services, visualizes their distribution, and highlights potential suspicious activities based on packet counts.


## Features

- Captures network packets and analyzes their content.
- Identifies common network protocols: TCP, UDP, ICMP, and others.
- Detects services based on well-known ports.
- Visualizes protocol and service distribution using bar charts.
- Provides security insights by highlighting unusual activity in the network traffic.



## Installation

Clone the repository:

```bash
  git clone https://github.com/HADIANA33M/FetchNut.git
  cd fetchnut
```
    
## Running Tests

To run tests, run the following command

```bash
  sudo python fetchnut.py

```


## API Reference

#### start packet capture

```python
    sniff(prn=packet_callback, count=100)

```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `prn` | `function` | **Required**. Callback function to execute for each packet |
| `count` | `int` | **Required**. Number of packets to capture |

#### Analyze Packet

```python
    packet_callback(packet)

```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `packet`      | `scapy.packet.Packet	` | **Required**. The packet to be analyzed |


#### Detect Service

```python
      detect_service(port)


```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `port`      | `int	` | **Required**. Port number to detect the service |


#### Plot Protocol Distribution

```python
  plt.bar(protocols, protocol_counts, color='blue')
  plt.xlabel('Protocols')
  plt.ylabel('Number of Packets')
  plt.title('Network Traffic Protocol Distribution')
  plt.show()



```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `protocols`      | `list	` | **Required**. List of protocol names |
| `protocol_counts`      | `list	` | **Required**. List of packet counts for each protocol |
| `color`      | `string	` | **Optional**. Color of the bars, default is 'blue' |





#### Plot Service Distribution

```python
  plt.bar(services, service_counts, color='green')
  plt.xlabel('Services')
  plt.ylabel('Number of Packets')
  plt.title('Detected Services Distribution')
  plt.show()




```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `services`      | `list	` | **Required**. List of service names |
| `services_counts`      | `list	` | **Required**. List of packet counts for each service |
| `color`      | `string	` | **Optional**. Color of the bars, default is 'green' |




#### Display Security Insights

```python
    for protocol, count in protocol_counter.items():
      if count > 50:
          print(f"Suspicious high number of {protocol} packets detected: {count}")

  for service, count in service_counter.items():
      if count > 50:
          print(f"Suspicious high number of packets for service {service} detected: {count}")





```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `protocol_counter`      | `counter	` | **Required**. Counter of protocol packets |
| `service_counter`      | `counter	` | **Required**. Counter of service packets |






# OT Monitoring

This project presents a simplified network traffic monitoring system designed for an OT/ICS environment. The application enables the simulation of communication between devices, analysis of captured traffic, anomaly detection, and presentation of results in a web-based dashboard.

## Project Objective

The objective of the project is to design and implement a complete data flow for a network monitoring system, including:

* traffic generation by simulated devices,
* packet capture and analysis,
* traffic metric aggregation,
* anomaly detection using rule-based and statistical methods,
* storage of results in a database,
* visualization of data in a live dashboard.

## System Architecture

The system consists of the following components:

* **device simulators** – generate network traffic and represent selected elements of an OT environment,
* **detector** – captures packets, calculates traffic metrics, and identifies anomalies,
* **API** – provides data to the frontend application and stores observations and events in the database,
* **PostgreSQL** – stores device configuration, traffic observations, and anomaly events,
* **frontend** – presents device status, current metrics, and live traffic charts.

## Application Workflow

1. After the environment is started, the containers run in parallel: database, simulators, detector, API, and frontend.
2. The simulators generate TCP/UDP traffic according to the assigned configuration and operating mode.
3. The detector listens on the selected network interface and analyzes ARP, IP, TCP, and UDP packets.
4. The collected data is aggregated into short time windows for individual flows.
5. Based on the calculated metrics, the detector produces traffic observations and identifies anomalies.
6. Observations and events are sent to the API and stored in the database.
7. The frontend periodically retrieves data from the API and presents it in a live dashboard.

## Anomaly Detection

Two anomaly detection approaches are implemented in the system:

* **heuristic rules** – used to detect, among others, traffic bursts, high jitter, large payloads, new IP addresses, new destination ports, IP/MAC mapping changes, and unexpected device silence,
* **statistical / ML model** – an optional mechanism based on `IsolationForest`, used to identify observations that deviate from the traffic pattern considered normal.

During the initial phase of operation, the detector enters a warmup stage in which a baseline of normal network behavior is established.

## Data Storage

The project uses PostgreSQL as a relational database. The most important tables include:

* `devices` – devices available in the system,
* `device_settings` – device operating parameters,
* `device_listen_ports` – listening ports,
* `traffic_observations` – short-term traffic observations,
* `anomaly_events` – detected anomaly events.

The `traffic_observations` table stores data only for a short period of time for the purposes of live visualization and learning the model of normal behavior. Older records are removed periodically.

## Technologies Used

The project uses the following technologies:

* Python,
* FastAPI,
* SQLAlchemy,
* PostgreSQL,
* Vue 3,
* TypeScript,
* Docker and Docker Compose,
* Scapy,
* scikit-learn.

## Outcome

The result of the project is a working prototype of a network traffic monitoring system that integrates simulation, traffic analysis, anomaly detection, persistent data storage, and live data visualization. The solution can serve as a basis for further research and development in the area of OT monitoring and industrial network cybersecurity.

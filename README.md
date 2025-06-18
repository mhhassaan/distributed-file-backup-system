<p align="left">
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask Badge"/>
  <img src="https://img.shields.io/badge/requests-2C5BB4?style=for-the-badge&logo=python&logoColor=white" alt="Requests Badge"/>
  <img src="https://img.shields.io/badge/Cryptography-FFD43B?style=for-the-badge&logo=python&logoColor=black" alt="Cryptography Badge"/>
  <img src="https://img.shields.io/badge/Watchdog-4B8BBE?style=for-the-badge&logo=python&logoColor=white" alt="Watchdog Badge"/>
</p>

# Distributed File Backup System

A fault-tolerant, distributed backup system built in Python as a semester project for Parallel & Distributed Computing. This application allows users to back up files from their local machine to multiple storage nodes, ensuring data integrity, security, and high availability. It features a full web-based user interface for management, automatic background synchronization of specified folders, and robust handling of large files.

## Features

-   [x] **Distributed & Replicated Storage:** Files are replicated across multiple storage nodes to prevent data loss from a single point of failure.
-   [x] **Fault Tolerance:** The system can withstand storage node failures. Restore requests are automatically redirected to healthy replicas, and a heartbeat mechanism tracks node health in real-time.
-   [x] **Client-Side Encryption:** Strong AES encryption is applied on the client-side before any data is transmitted. Encryption is password-based, with keys derived using PBKDF2, ensuring only the user can access their data.
-   [x] **Large File Support (Chunking):** Files larger than 30MB are automatically broken into 4MB chunks, allowing for the efficient backup of files of virtually any size without memory limitations.
-   [x] **Automatic Background Sync:** Users can designate multiple folders to be monitored. The system uses `watchdog` to detect file creations, modifications, or deletions in real-time and automatically syncs the changes.
-   [x] **Full Web-Based UI:** A clean, modern user interface built with Flask allows for all operations:
    -   Manual single-file uploads.
    -   Managing a watchlist of folders for automatic sync.
    -   A categorized overview of all backed-up files.
    -   Restoring and deleting files.
    -   Viewing the real-time status of all storage nodes.
-   [x] **Easy Deployment:** Comes with simple batch scripts to automate the setup and launching of all system components.

## System Architecture

The application is composed of three main components that work together:

1.  **Coordinator Node (`coordinator.py`)**
    -   Acts as the central "brain" or orchestrator of the system.
    -   It does not store any file data itself.
    -   Maintains a database of all file metadata (hashes, chunk lists, locations).
    -   Tracks the health and status of all registered Storage Nodes via a heartbeat mechanism.
    -   Assigns Storage Nodes for new backups using a round-robin strategy to distribute the load.

2.  **Storage Nodes (`storage_node.py`)**
    -   These are the "workhorses" that perform the physical storage.
    -   They provide a simple API to `store` and `retrieve` data blobs by their SHA-256 hash.
    -   They have no knowledge of files, users, or the overall system state; they only store the data they are given.
    -   Multiple instances of this script can be run to scale the system's storage capacity and redundancy.

3.  **Storage Nodes (`storage_node_dropbox.py`)**
    -   Same as 'storage_node.py' only difference is instead of local nodes, cloud nodes are build on dropbox.

3.  **Client Application (`web_ui.py`)**
    -   This is the user-facing component, providing a web dashboard for all interactions.
    -   It handles all client-side logic: hashing, chunking, and encryption.
    -   It communicates with the Coordinator to get instructions and log metadata.
    * It communicates directly with the Storage Nodes to upload and download file data.
    * It runs a background `watchdog` thread to monitor local folders for automatic synchronization.

## Tech Stack

-   **Language:** Python 3
-   **Web Framework:** Flask
-   **Networking:** Requests
-   **Encryption:** Cryptography
-   **File System Monitoring:** Watchdog

---
## How to Run

1.  **On Windows OS:**
    **a**. Copy the entire project folder over.
    **b**. Double-click **`setup.bat`** and wait for it to complete.
2.  **To start the application with local nodes:** Double-click **`start_all.bat`**. This will open the four server windows with. 
3.  **To start the application with cloud nodes:** Open terminal in root folder and write in command `.\start.bat 4`, here 4 indicates 4 nodes. 
4.  **Access the UI:** Open your web browser and navigate to **`http://127.0.0.1:5000`**.
5.  **To stop the application:** Close all CMD windows.

## Group Members

-   Muhammad Hassan – (FA22-BCS-100) 
-   Baseer Ahmed Tahir – (FA22-BCS-104)

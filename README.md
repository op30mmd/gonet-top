# gonet-top

`gonet-top` is a powerful, terminal-based network monitoring tool for Windows, designed to give you a real-time, detailed view of network activity on your system. It provides an at-a-glance summary of which processes are using the network, their connection counts, and their data transfer rates.

![gonet-top screenshot](https://i.imgur.com/your-screenshot.png) <!-- placeholder -->

## Features

- **Real-time Monitoring**: Continuously updates to show the latest network activity.
- **Process-Specific Details**: See exactly which processes are making TCP and UDP connections.
- **Multiple Views**:
    - **Summary View**: A high-level overview of all network-active processes.
    - **Detailed View**: A more in-depth look at connection stats, including established connections and top remote hosts.
    - **Connections View**: A list of all active connections for a selected process.
- **I/O Rates & Totals**: Track upload and download speeds, as well as total data sent and received for each process.
- **Dynamic Sorting**: Sort processes by total connections, upload rate, download rate, process name, PID, or total I/O.
- **Admin-Aware**: Detects if it's running with administrator privileges and notifies the user about potential limitations.
- **Customizable**: Adjust the refresh rate and sorting delay to your preference.

## Getting Started

### Prerequisites

- Windows operating system.
- Go (version 1.24.3 or later) installed.

### Building from Source

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/your-username/gonet-top.git
    cd gonet-top
    ```

2.  **Build the executable:**
    ```sh
    go build -o gonet-top.exe .
    ```

### Running `gonet-top`

Simply run the compiled executable from your terminal:

```sh
./gonet-top.exe
```

For the best experience and most detailed information, it is recommended to run `gonet-top` in a terminal with administrator privileges.

## Controls

`gonet-top` is controlled with keyboard shortcuts:

| Key(s)        | Action                                           |
|---------------|--------------------------------------------------|
| `q` / `Ctrl+c`| Quit the application.                            |
| `↑` / `k`     | Navigate up the process list.                    |
| `↓` / `j`     | Navigate down the process list.                  |
| `Enter` / `d` | Toggle the detailed information panel for the selected process. |
| `Tab`         | Cycle through the **Summary**, **Detailed**, and **Connections** views. |
| `s`           | Cycle through the sorting modes (Connections, Upload, Download, Process, PID, Total I/O). |
| `r`           | Enter **Settings Mode**.                         |

### Settings Mode

When in Settings Mode, the following controls are available:

| Key(s)        | Action                                           |
|---------------|--------------------------------------------------|
| `↑` / `↓`     | Increase/decrease the refresh delay.             |
| `←` / `→`     | Increase/decrease the sort delay.                |
| `Enter`       | Exit Settings Mode.                              |

## CI/CD

This project uses GitHub Actions to automatically build and test the application on every push to the `main` or `master` branches.

When a push is made to `main` or `master`, the workflow also automatically creates a new GitHub Release, tagged with the commit hash, and uploads the compiled `gonet-top.exe` binary as a release asset. This makes it easy to download the latest version of the tool directly from the repository's releases page.

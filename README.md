# ProtonVPN Wireguard Configuration Downloader

A tool to automatically download wireguard configuration files for all available VPN servers from ProtonVPN.

**NOTE**
This script is intended to be used in Linux environments only.

## Environment Variables

- `USERNAME`: username for connnecting to ProtonVPN account
- `PASSWORD`
- `WORKDIR`: location to store configuration files. (default: /data)
- `WIREGUARD_PORT`: Port of the wireguard configuration files (default: 51820).This allows to choose the wireguard port for the configuration files rather than leaving it to the ProtonVPN library which often defaults to the first available port in the session object.

## Usage
- Build the image
    ```sh
    docker build -t protonvpn-wireguard-config-downloader .
    ```
- Download the configuration files
    ```sh
    docker run --rm -e USERNAME=abcd@efg -e PASSWORD=pa55word -v ./proton:/data protonvpn-wireguard-config-downloader protonvpn-wireguard-configs
    ```

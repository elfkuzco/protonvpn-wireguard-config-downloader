import argparse
import asyncio
import logging
from pathlib import Path

from protonvpn_wireguard_config_downloader import logger
from protonvpn_wireguard_config_downloader.__about__ import __version__
from protonvpn_wireguard_config_downloader.protonvpn import (
    login,
    logout,
    save_vpn_server_wireguard_config,
    vpn_servers,
)
from protonvpn_wireguard_config_downloader.settings import Settings


async def download_vpn_wireguard_configs(
    username: str, password: str, wireguard_port: int, work_dir: Path
) -> None:
    """Download Wireguard configuration files for all VPN servers."""
    session = await login(username, password)
    try:
        logger.debug("Fetching available VPN servers for client...")
        for vpn_server in vpn_servers(session, wireguard_port):
            save_vpn_server_wireguard_config(session, vpn_server, work_dir)
    finally:
        logger.debug("Logging out...")
        await logout(session)
        logger.info("Successfully logged out client.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", help="Show verbose output", action="store_true"
    )
    parser.add_argument(
        "--version",
        help="Show version and exit.",
        action="version",
        version="%(prog)s " + __version__,
    )
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    asyncio.run(
        download_vpn_wireguard_configs(
            Settings.USERNAME,
            Settings.PASSWORD,
            Settings.WIREGUARD_PORT,
            Settings.WORKDIR,
        )
    )

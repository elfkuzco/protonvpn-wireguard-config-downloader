import argparse
import asyncio
import logging

from protonvpn_wireguard_config_downloader import logger
from protonvpn_wireguard_config_downloader.__about__ import __version__
from protonvpn_wireguard_config_downloader.protonvpn import (
    login,
    logout,
    vpn_servers,
)
from protonvpn_wireguard_config_downloader.saver import (
    FileSaver,
    StdoutSaver,
    VPNServerSaver,
)
from protonvpn_wireguard_config_downloader.settings import Settings


async def download_vpn_wireguard_configs(
    username: str, password: str, wireguard_port: int, saver: VPNServerSaver
) -> None:
    """Download Wireguard configuration files for all VPN servers."""
    session = await login(username, password)
    try:
        logger.debug("Fetching available VPN servers for client...")
        for vpn_server in vpn_servers(session, wireguard_port):
            saver.save(session, vpn_server)
    finally:
        await logout(session)


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

    parser.add_argument(
        "-l", "--list", help="List all the servers.", action="store_true"
    )

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    saver: VPNServerSaver
    if args.list:
        saver = StdoutSaver()
    else:
        saver = FileSaver(Settings.WORKDIR)

    asyncio.run(
        download_vpn_wireguard_configs(
            Settings.USERNAME,
            Settings.PASSWORD,
            Settings.WIREGUARD_PORT,
            saver,
        )
    )

import argparse
import asyncio
import logging

from proton.vpn.session.servers.types import (  # pyright: ignore[reportMissingTypeStubs]
    ServerFeatureEnum,
)

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
    username: str,
    password: str,
    wireguard_port: int,
    saver: VPNServerSaver,
    server_features: set[ServerFeatureEnum],
) -> None:
    """Download Wireguard configuration files for all VPN servers."""
    session = await login(username, password)
    try:
        logger.debug("Fetching available VPN servers for client...")
        for vpn_server in vpn_servers(session, wireguard_port, server_features):
            saver.save(session, vpn_server)
    finally:
        await logout(session)


def parse_features(features: str) -> set[ServerFeatureEnum]:
    """Parse comma-seperated list of features."""
    features_map = {
        "secure-core": ServerFeatureEnum.SECURE_CORE,
        "tor": ServerFeatureEnum.TOR,
        "p2p": ServerFeatureEnum.P2P,
        "streaming": ServerFeatureEnum.STREAMING,
        "ipv6": ServerFeatureEnum.IPV6,
    }

    try:
        return {features_map[feature] for feature in features.strip().split(",")}
    except KeyError as e:
        raise ValueError(f"{e.args[0]} is not a supported feature.") from e


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

    parser.add_argument(
        "--features",
        help="Comma-seperated list of features for servers.",
        metavar="secure-core,tor,p2p,ipv6,streaming",
        type=parse_features,
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
            args.features or set(),
        )
    )

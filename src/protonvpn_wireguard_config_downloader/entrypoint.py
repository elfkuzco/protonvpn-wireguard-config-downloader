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
    *,
    username: str,
    password: str,
    wireguard_port: int,
    saver: VPNServerSaver,
    server_features: set[ServerFeatureEnum],
    threshold: int,
) -> None:
    """Download Wireguard configuration files for all VPN servers."""
    session = await login(username, password)
    try:
        logger.debug("Fetching available VPN servers for client...")
        for vpn_server in vpn_servers(
            session=session,
            wireguard_port=wireguard_port,
            server_features=server_features,
            threshold=threshold,
        ):
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
        return {
            features_map[feature.strip().lower()]
            for feature in features.strip().split(",")
        }
    except KeyError as e:
        raise ValueError(f"{e.args[0]} is not a supported feature.") from e


def parse_threshold(threshold: str) -> int:
    """Parse the threshold of server score."""
    try:
        score = int(threshold)
    except ValueError as e:
        raise TypeError(f"{e.args[0]} is not a valid number.") from e

    if score > 100:  # noqa: PLR2004
        raise ValueError("threshold cannot be greater than 100.")

    return score


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

    parser.add_argument(
        "--threshold",
        help=(
            "Select only servers whose that are below the score. (1-100). "
            "The lower the number is the better is for establishing a connection."
        ),
        type=parse_threshold,
        default=100,
        metavar="score",
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
            username=Settings.USERNAME,
            password=Settings.PASSWORD,
            wireguard_port=Settings.WIREGUARD_PORT,
            saver=saver,
            server_features=args.features or set(),
            threshold=args.threshold,
        )
    )

from abc import ABC, abstractmethod
from pathlib import Path

from proton.vpn.connection.vpnconfiguration import (  # pyright: ignore[reportMissingTypeStubs]
    WireguardConfig,
)
from proton.vpn.core.connection import (  # pyright: ignore[reportMissingTypeStubs]
    VPNServer,
)
from proton.vpn.session import VPNSession  # pyright: ignore[reportMissingTypeStubs]

from protonvpn_wireguard_config_downloader import logger


class VPNServerSaver(ABC):
    """Abstract base class for saving VPN server."""

    @abstractmethod
    def save(self, session: VPNSession, vpn_server: VPNServer):
        """Save the given VPN server."""


class StdoutSaver(VPNServerSaver):
    """Writes VPN data to stdout."""

    def save(
        self,
        session: VPNSession,  # noqa: ARG002
        vpn_server: VPNServer,
    ):
        print(f"{vpn_server.server_name}.conf")  # noqa: T201


class FileSaver(VPNServerSaver):
    def __init__(self, dest_dir: Path):
        self.dest_dir = dest_dir

    def save(self, session: VPNSession, vpn_server: VPNServer):
        """Save the Wireguard config for the the VPN server to filesystem."""
        logger.debug(
            f"Saving configuration file for VPN server: {vpn_server.server_name}"
        )
        config = WireguardConfig(
            vpn_server, session.vpn_account.vpn_credentials, None, use_certificate=True
        )
        dest_fpath = self.dest_dir / f"{vpn_server.server_name}.conf"
        dest_fpath.write_text(config.generate(), encoding="utf-8")
        logger.info(
            f"Saved configuration file for VPN server: {vpn_server.server_name},  "
            f"name: {dest_fpath.name}"
        )

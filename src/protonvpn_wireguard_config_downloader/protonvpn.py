# pyright: strict, reportMissingTypeStubs=false, reportUnknownMemberType=false, reportOptionalSubscript=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
from collections.abc import Generator
from pathlib import Path
from typing import cast

from proton.sso import ProtonSSO
from proton.vpn.connection.vpnconfiguration import WireguardConfig
from proton.vpn.core.connection import VPNServer
from proton.vpn.session import VPNSession

from protonvpn_wireguard_config_downloader import logger
from protonvpn_wireguard_config_downloader.settings import Settings


async def login(username: str, password: str) -> VPNSession:
    """Log in to Proton VPN account."""
    logger.info("Logging in to ProtonVPN...")
    sso = ProtonSSO(
        user_agent=Settings.USER_AGENT, appversion=Settings.PROTONVPN_APP_VERSION
    )
    session = cast(VPNSession, sso.get_session(username, override_class=VPNSession))
    logger.debug("Authenticating credentials with ProtonVPN.")
    await session.async_authenticate(username, password)
    logger.debug("Fetching client session data.")
    await session.fetch_session_data()
    logger.info("Logged in to ProtonVPN.")
    return session


async def logout(session: VPNSession) -> None:
    """Log out from the Proton VPN account."""
    if session.authenticated:
        await session.async_logout()


def wireguard_port_is_available(session: VPNSession, port: int) -> bool:
    """Check that the wireguard port is available in the client config."""
    return port in session.client_config.wireguard_ports.udp


def vpn_servers(
    session: VPNSession,
    wireguard_port: int,
) -> Generator[VPNServer, None, None]:
    """Generate the available VPN servers for this account.

    Raises:
        ValueError: Specified wireguard port is not available for this client.
    """
    client_config = session.client_config
    if wireguard_port not in client_config.wireguard_ports.udp:
        raise ValueError(f"Port {wireguard_port} is not available in client config.")

    logical_servers = (
        server
        for server in session.server_list.logicals
        if server.enabled and server.tier <= session.server_list.user_tier
    )
    return (
        VPNServer(
            server_ip=physical_server.entry_ip,
            domain=physical_server.domain,
            x25519pk=physical_server.x25519_pk,
            openvpn_ports=client_config.openvpn_ports,
            wireguard_ports=[
                wireguard_port
            ],  # pyright: ignore[reportGeneralTypeIssues, reportArgumentType]
            server_id=logical_server.id,
            server_name=f"{logical_server.exit_country.lower()}-{logical_server.name}",
            label=physical_server.label,
        )
        for logical_server in logical_servers
        for physical_server in logical_server.physical_servers
    )


def save_vpn_server_wireguard_config(
    session: VPNSession, vpn_server: VPNServer, dest_dir: Path
) -> Path:
    """Save the Wireguard config for the VPN server."""
    logger.debug(f"Saving configuration file for VPN server: {vpn_server.server_name}")
    config = WireguardConfig(
        vpn_server, session.vpn_account.vpn_credentials, None, use_certificate=True
    )
    dest_fpath = dest_dir / f"{vpn_server.server_name}.conf"
    dest_fpath.write_text(config.generate(), encoding="utf-8")
    logger.info(
        f"Saved configuration file for VPN server: {vpn_server.server_name},  "
        f"name: {dest_fpath.name}"
    )
    return dest_fpath

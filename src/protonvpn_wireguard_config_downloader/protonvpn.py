from collections.abc import Generator
from typing import cast

from proton.sso import ProtonSSO  # pyright: ignore[reportMissingTypeStubs]
from proton.vpn.core.connection import (  # pyright: ignore[reportMissingTypeStubs]
    VPNServer,
)
from proton.vpn.session import VPNSession  # pyright: ignore[reportMissingTypeStubs]
from proton.vpn.session.servers.types import (  # pyright: ignore[reportMissingTypeStubs]
    ServerFeatureEnum,
)

from protonvpn_wireguard_config_downloader import logger
from protonvpn_wireguard_config_downloader.exceptions import (
    ProtonVPNAuthenticationError,
)
from protonvpn_wireguard_config_downloader.settings import Settings


async def login(username: str, password: str) -> VPNSession:
    """Log in to Proton VPN account."""

    logger.debug("Logging in to ProtonVPN...")
    sso = ProtonSSO(
        user_agent=Settings.USER_AGENT, appversion=Settings.PROTONVPN_APP_VERSION
    )
    session = cast(VPNSession, sso.get_session(username, override_class=VPNSession))
    logger.debug("Authenticating credentials with ProtonVPN.")
    login_result = await session.login(username, password)  # pyright: ignore[reportUnknownMemberType, reportArgumentType]
    if not login_result.authenticated:
        raise ProtonVPNAuthenticationError("Authentication credentials are invalid.")

    if login_result.twofa_required:
        twofa_code = input("Enter 2FA code for account: ")
        logger.debug("Verifying 2FA code...")
        login_result = await session.provide_2fa(twofa_code)
        if login_result.twofa_required:
            raise ProtonVPNAuthenticationError("Invalid 2FA code.")

    if not login_result.success:
        raise ProtonVPNAuthenticationError("Unable to authenticate to ProtonVPN.")

    logger.debug("Fetching client session data.")
    await session.fetch_session_data()  # pyright: ignore[reportUnknownMemberType]
    logger.info("Logged in to ProtonVPN.")
    return session


async def logout(session: VPNSession) -> None:
    """Log out from the Proton VPN account."""
    if session.authenticated:
        logger.debug("Logging out...")
        await session.async_logout()  # pyright: ignore[reportUnknownMemberType]
    logger.info("Logged out from ProtonVPN.")


def vpn_servers(
    *,
    session: VPNSession,
    wireguard_port: int,
    server_features: set[ServerFeatureEnum],
    threshold: int,
) -> Generator[VPNServer, None, None]:
    """Generate the available VPN servers for this account.

    Raises:
        ValueError: Specified wireguard port is not available for this client.
    """
    client_config = session.client_config
    if (
        wireguard_port not in client_config.wireguard_ports.udp  # pyright: ignore[reportUnknownMemberType]
    ):  # pyright: ignore[reportUnknownMemberType]
        raise ValueError(f"Port {wireguard_port} is not available in client config.")

    # Build up the list of servers that:
    # - are enabled
    # - are less than or equal to the user tier
    # - have all the specified features
    # - have scores lower than threshold
    logical_servers = (
        server
        for server in session.server_list.logicals
        if server.enabled
        and server.tier <= session.server_list.user_tier
        and len(server_features) <= len(server.features)
        and len(server_features & set(server.features)) == len(server_features)
        and server.load <= threshold
    )

    return (
        VPNServer(
            server_ip=physical_server.entry_ip,
            domain=physical_server.domain,
            x25519pk=physical_server.x25519_pk,
            openvpn_ports=client_config.openvpn_ports,  # pyright: ignore[reportArgumentType, reportUnknownArgumentType]
            wireguard_ports=[wireguard_port],  # pyright: ignore[reportGeneralTypeIssues, reportArgumentType]
            server_id=logical_server.id,
            server_name=f"{logical_server.entry_country.lower()}-{logical_server.name}",
            label=physical_server.label,
        )
        for logical_server in logical_servers
        for physical_server in logical_server.physical_servers
    )

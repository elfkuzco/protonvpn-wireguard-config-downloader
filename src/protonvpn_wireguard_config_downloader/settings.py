import os
from pathlib import Path
from typing import Any

import distro


def getenv(key: str, *, mandatory: bool = False, default: Any = None) -> Any:
    value = os.getenv(key, default=default)

    if mandatory and not value:
        raise OSError(f"Please set the {key} environment variable")

    return value


class Settings:
    """Task worker configuration"""

    USERNAME = getenv("USERNAME", mandatory=True)
    PASSWORD = getenv("PASSWORD", mandatory=True)
    DEBUG = bool(getenv("DEBUG", default=False))
    WORKDIR = Path(getenv("WORKDIR", default="/data")).resolve()
    PROTONVPN_VERSION = getenv("PROTONVPN_APP_VERSION", default="4.4.4")
    PROTONVPN_APP_VERSION = f"LinuxVPN_{PROTONVPN_VERSION}"
    USER_AGENT = (
        f"ProtonVPN/{PROTONVPN_VERSION} (Linux; {distro.name()}/{distro.version()})"
    )
    WIREGUARD_PORT = int(getenv("WIREGUARD_PORT", default=51820))

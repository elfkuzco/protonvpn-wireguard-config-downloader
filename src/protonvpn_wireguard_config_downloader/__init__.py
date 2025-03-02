import logging

from protonvpn_wireguard_config_downloader.settings import Settings

logger = logging.getLogger("protonvpn_wireguard_config_downloader")

if not logger.hasHandlers():
    logger.setLevel(logging.DEBUG if Settings.DEBUG else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s: %(levelname)s] %(message)s"))
    logger.addHandler(handler)

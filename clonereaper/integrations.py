from .config import Config

def trigger_media_server_scan(config: Config):
    """Triggers a library scan on configured media servers."""
    if not config.media_server_config.get("enabled"):
        return

    print("Media server integration is enabled (implementation pending).")
    print(
        "You would configure server URLs and API keys for Plex/Jellyfin/Emby."
    )
    # Example using requests library:
    # import requests
    #
    # for server in config.media_server_config.get('servers', []):
    #     if server['type'] == 'plex':
    #         url = f"{server['url']}/library/sections/all/refresh?X-Plex-Token={server['api_key']}"
    #         try:
    #             requests.get(url)
    #             print(f"Triggered Plex scan on {server['url']}")
    #         except requests.RequestException as e:
    #             logging.error(f"Failed to trigger Plex scan: {e}")

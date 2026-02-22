import tls_client
import threading
import time
from typing import List, Dict, Optional
import json
import os

# Base cookies and headers
COOKIES = {
    '__dcfduid': 'a598dfd0f4b611f09bab3fc1d23c209a',
    '__sdcfduid': 'a598dfd1f4b611f09bab3fc1d23c209ae62943a2dc6d970ec5d6ba06f55dc4bcc683b40d98249114ee8f40a50ac0ed0c',
    'locale': 'en-US',
    '_cfuvid': 'OHooIS_j66BhOTWPar5rOVymnAjvSJhB1TWIxMYvp4Y-1768818570964-0.0.1.1-604800000',
    'cf_clearance': 'kUEwYVBxSGViRDMLe02rXd1rpgs9LhvzXpvGYzevmf8-1768819110-1.2.1.1-VO0eXMx6xOq3EMcZUWDzs4XXdQ3Vt0NyVDs_OGVF_ugLhpjJvzIW0SGY_fKa0YATYa1IrPwhkYQK7Bov9KrsKQ3pYjEDxnH9WVxS2Qx7DK5ZAOMUMRvDF9o5j7zvsPWlErtnTqk06CIavCDndvmUJSUcJuGQBedZapem9qVE6L2SILp.hTg3N2KN88Tnp38jpSEHahhKkWtRoFWMHOT88XSNaoknZtdE5pJnyBpPWsk',
}

BASE_HEADERS = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.6',
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'priority': 'u=1, i',
    'referer': 'https://discord.com/channels/1462228144588062752/1462228789676212412',
    'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'sec-gpc': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Paris',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiaGFzX2NsaWVudF9tb2RzIjpmYWxzZSwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzE0NC4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTQ0LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6Imh0dHBzOi8vZGlzY29yZC5jb20vIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiZGlzY29yZC5jb20iLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjo0ODY4MjcsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGwsImNsaWVudF9sYXVuY2hfaWQiOiIzOTc5ZjRiMC01NDdiLTRhYzUtYTk2Zi04YTU4YzFiNzQ1NzIiLCJsYXVuY2hfc2lnbmF0dXJlIjoiNGUxNTYwMDUtNjU2Mi00Njg2LTljNzYtNWEyZDhjMjZhNTZhIiwiY2xpZW50X2FwcF9zdGF0ZSI6ImZvY3VzZWQiLCJjbGllbnRfaGVhcnRiZWF0X3Nlc3Npb25faWQiOiI2YzQ0MzdiMy1hODk2LTRmNmItOWQ2Yy0wMmRiYmQ5MzdlYjYifQ==',
}

# Global session - used for all requests
session1 = tls_client.Session(
    random_tls_extension_order=True
)

# Set cookies in session
for cookie_name, cookie_value in COOKIES.items():
    session1.cookies.set(cookie_name, cookie_value)

# Lock to protect session access in multithreading
session_lock = threading.Lock()

# Base URL for Discord API
DISCORD_API_BASE = "https://discord.com/api/v10"

# Default config values
DEFAULT_CONFIG = {
    "message_to_send": "Hello!",
    "delay_between_conversations": 1,
    "delay_between_channels": 0.5,
}

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# Global list for tokens
tokens: List[str] = []


def load_config() -> Dict:
    """Load configuration from config.json"""
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return {**DEFAULT_CONFIG, **config}
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load config.json: {e}. Using defaults.")
    return DEFAULT_CONFIG.copy()


def load_tokens(filename: str = "tokens.txt") -> List[str]:
    """Load tokens from tokens.txt file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            tokens_list = [
                line.strip() for line in f.readlines()
                if line.strip() and not line.strip().startswith('#')
            ]
        return tokens_list
    except FileNotFoundError:
        print(f"Error: File {filename} does not exist!")
        return []


def make_request(method: str, url: str, token: str,
                data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Optional[Dict]:
    """Make HTTP request to Discord API using session1 with headers and cookies"""
    default_headers = BASE_HEADERS.copy()
    default_headers['authorization'] = token

    if headers:
        default_headers.update(headers)

    try:
        with session_lock:
            if method.upper() == "GET":
                response = session1.get(url, headers=default_headers, cookies=COOKIES)
            elif method.upper() == "POST":
                response = session1.post(url, headers=default_headers, json=data, cookies=COOKIES)
            else:
                response = session1.request(method, url, headers=default_headers, json=data, cookies=COOKIES)

        if response.status_code == 204:
            return {}

        if not response.text:
            return {}

        try:
            return response.json()
        except Exception:
            return {"raw": response.text}
    except Exception as e:
        print(f"  x Request error: {e}")
        return None


def get_user_info(token: str) -> Optional[Dict]:
    """Get user information"""
    url = f"{DISCORD_API_BASE}/users/@me"
    return make_request("GET", url, token)


def get_dm_channels(token: str) -> List[Dict]:
    """Get all DM conversations"""
    url = f"{DISCORD_API_BASE}/users/@me/channels"
    result = make_request("GET", url, token)
    if result and isinstance(result, list):
        return [ch for ch in result if ch.get("type") == 1]
    return []


def send_dm_message(token: str, channel_id: str,
                   message: str, recipient_name: str = "Unknown",
                   delay_conversations: float = 1) -> bool:
    """Send a message in a DM conversation"""
    url = f"{DISCORD_API_BASE}/channels/{channel_id}/messages"
    data = {"content": message}

    result = make_request("POST", url, token, data)
    if result:
        print(f"  [OK] Message sent in DM: {recipient_name}")
        return True
    else:
        print(f"  [FAIL] DM send failed: {recipient_name}")
        return False


def get_guilds(token: str) -> List[Dict]:
    """Get all guilds (servers)"""
    url = f"{DISCORD_API_BASE}/users/@me/guilds"
    result = make_request("GET", url, token)
    if result and isinstance(result, list):
        return result
    return []


def get_guild_channels(token: str, guild_id: str) -> List[Dict]:
    """Get all text channels of a server that the user can see"""
    url = f"{DISCORD_API_BASE}/guilds/{guild_id}/channels"
    result = make_request("GET", url, token)
    if result and isinstance(result, list):
        return [ch for ch in result if ch.get("type") == 0]
    return []


def get_guild_member(token: str, guild_id: str) -> Optional[Dict]:
    """Get member info in a server"""
    user_info = get_user_info(token)
    if not user_info:
        return None

    user_id = user_info.get("id")
    if not user_id:
        return None

    url = f"{DISCORD_API_BASE}/guilds/{guild_id}/members/{user_id}"
    return make_request("GET", url, token)


def check_channel_permission(token: str, channel_id: str) -> bool:
    """Check if user has permission to send messages in a channel"""
    url = f"{DISCORD_API_BASE}/channels/{channel_id}"
    channel_info = make_request("GET", url, token)

    if not channel_info:
        return False

    if channel_info.get("type") == 0:
        return True

    return False


def send_channel_message(token: str, channel_id: str,
                         message: str, channel_name: str = "Unknown",
                         guild_name: str = "Unknown") -> bool:
    """Send a message in a server channel after checking permissions"""
    if not check_channel_permission(token, channel_id):
        print(f"  [FAIL] No permission to send in #{channel_name} ({guild_name})")
        return False

    url = f"{DISCORD_API_BASE}/channels/{channel_id}/messages"
    data = {"content": message}

    result = make_request("POST", url, token, data)
    if result:
        print(f"  [OK] Message sent in #{channel_name} ({guild_name})")
        return True
    else:
        print(f"  [FAIL] Channel send failed #{channel_name} ({guild_name})")
        return False


def process_dms(token: str, user_info: Dict, message: str, delay_conversations: float):
    """Process all DM conversations"""
    username = user_info.get("username", "Unknown")
    print(f"[{username}] Scanning DM conversations...")

    dm_channels = get_dm_channels(token)
    dm_count = 0

    for channel in dm_channels:
        dm_count += 1
        recipients = channel.get("recipients", [])
        recipient_name = recipients[0].get("username", "Unknown") if recipients else "Unknown"

        print(f"  [{dm_count}] Sending to {recipient_name}...")
        send_dm_message(token, channel["id"], message, recipient_name)
        time.sleep(delay_conversations)

    print(f"[{username}] {dm_count} DM conversations processed")


def process_single_server(token: str, guild: Dict, message: str, server_index: int, delay_channels: float) -> int:
    """Process a single server and return the number of channels processed"""
    guild_id = guild.get("id")
    guild_name = guild.get("name", "Unknown")

    print(f"  [{server_index}] Server: {guild_name}")

    channels = get_guild_channels(token, guild_id)
    print(f"    -> {len(channels)} visible text channels found")

    channel_count = 0
    for channel in channels:
        channel_count += 1
        channel_id = channel.get("id")
        channel_name = channel.get("name", "Unknown")

        print(f"    [{channel_count}] Channel: #{channel_name}")

        send_channel_message(token, channel_id, message, channel_name, guild_name)
        time.sleep(delay_channels)

    return channel_count


def process_servers(token: str, user_info: Dict, message: str, delay_channels: float):
    """Process all servers and their channels in batches of 5 in parallel"""
    username = user_info.get("username", "Unknown")
    print(f"[{username}] Scanning servers...")

    guilds = get_guilds(token)
    total_servers = len(guilds)
    total_channels = 0

    batch_size = 5
    server_index = 0

    for i in range(0, total_servers, batch_size):
        batch = guilds[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        print(f"\n  -> Processing batch {batch_num} ({len(batch)} server(s))...")

        threads = []
        results = {}

        def process_with_result(guild, idx):
            results[idx] = process_single_server(token, guild, message, idx, delay_channels)

        for guild in batch:
            server_index += 1
            thread = threading.Thread(
                target=process_with_result,
                args=(guild, server_index),
                daemon=True
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        batch_channels = sum(results.values())
        total_channels += batch_channels
        print(f"  [OK] Batch {batch_num} completed ({batch_channels} channels processed)")

    print(f"[{username}] {total_servers} servers and {total_channels} channels processed")


def process_token(token: str, message: str, mode: int, config: Dict):
    """Process a Discord token
    mode: 1 = DMs only, 2 = Servers only, 3 = Both
    """
    delay_conversations = config.get("delay_between_conversations", 1)
    delay_channels = config.get("delay_between_channels", 0.5)

    try:
        user_info = get_user_info(token)
        if not user_info:
            print(f"[FAIL] Invalid token: {token[:20]}...")
            return

        username = user_info.get("username", "Unknown")
        user_id = user_info.get("id", "Unknown")
        print(f"\n[{username}] Connected successfully! (ID: {user_id})")

        if mode == 1 or mode == 3:
            process_dms(token, user_info, message, delay_conversations)

        if mode == 2 or mode == 3:
            process_servers(token, user_info, message, delay_channels)

        print(f"[{username}] Processing complete!")

    except Exception as e:
        print(f"[FAIL] Error with token {token[:20]}...: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main function"""
    global tokens

    config = load_config()
    message_to_send = config.get("message_to_send", "Hello!")
    delay_conversations = config.get("delay_between_conversations", 1)
    delay_channels = config.get("delay_between_channels", 0.5)

    print("=" * 60)
    print("Discord Mass Messenger (REST API with tls_client)")
    print("=" * 60)

    tokens = load_tokens("tokens.txt")

    if not tokens:
        print("No tokens found in tokens.txt!")
        return

    print(f"\n{len(tokens)} token(s) loaded")

    print("\n" + "=" * 60)
    print("Choose send mode:")
    print("  1 - DMs only")
    print("  2 - Servers only")
    print("  3 - Both (DMs + Servers)")
    print("=" * 60)

    while True:
        choice = input("\nYour choice (1/2/3): ").strip()
        if choice in ['1', '2', '3']:
            mode = int(choice)
            break
        else:
            print("Invalid choice! Please enter 1, 2 or 3.")

    mode_names = {
        1: "DMs only",
        2: "Servers only",
        3: "DMs + Servers"
    }
    print(f"\n[OK] Mode selected: {mode_names[mode]}")

    message = input(f"\nMessage to send (Enter to use '{message_to_send}' from config): ").strip()
    if not message:
        message = message_to_send

    print(f"\nMessage configured: {message}")
    print(f"Delay between conversations: {delay_conversations}s")
    print(f"Delay between channels: {delay_channels}s")

    confirm = input("\nContinue? (y/n): ").strip().lower()
    if confirm not in ('y', 'yes'):
        print("Cancelled.")
        return

    print("\n" + "=" * 60)
    print("Starting processing with threads...")
    print("=" * 60 + "\n")

    threads = []
    for i, token in enumerate(tokens, 1):
        thread = threading.Thread(
            target=process_token,
            args=(token, message, mode, config),
            name=f"Token-{i}",
            daemon=True
        )
        threads.append(thread)
        thread.start()
        print(f"Thread {i} started for token {token[:20]}...")
        time.sleep(0.5)

    for thread in threads:
        thread.join()

    print("\n" + "=" * 60)
    print("All threads completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()

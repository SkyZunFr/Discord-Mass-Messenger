# Discord Mass Messenger

A Discord mass messaging tool (server/dms)

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Edit `config.json` to set:
   - `message_to_send`: Default message to send
   - `delay_between_conversations`: Delay in seconds between DM sends
   - `delay_between_channels`: Delay in seconds between channel sends

3. Add your Discord tokens to `tokens.txt` (one per line)

4. Run:
   ```
   python main.py
   ```

## Configuration (config.json)

| Option | Description | Default |
|--------|-------------|---------|
| message_to_send | Message to send | "Hello!" |
| delay_between_conversations | Delay in seconds between DM conversations | 1 |
| delay_between_channels | Delay in seconds between channels | 0.5 |

## Files

- `main.py` - Main script
- `config.json` - Configuration (message, delays)
- `tokens.txt` - Discord tokens (one per line)
- `requirements.txt` - Python dependencies

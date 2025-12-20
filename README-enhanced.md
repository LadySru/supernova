# Discord Music Bot 🎵

A feature-rich Discord bot that plays YouTube videos as music in voice channels with slash commands and an interactive music player channel.

## Features

- 🎵 Play YouTube videos by URL or search query
- 💬 Slash commands and traditional prefix commands
- 🎮 Interactive music player channel with buttons
- ⏸️ Pause and resume functionality
- 📃 Queue system for multiple songs
- ⏭️ Skip and stop commands
- 📊 Real-time player status updates
- 🎨 Beautiful embedded messages

## Slash Commands

The bot supports modern Discord slash commands:

- `/play <song>` - Play a song from YouTube (URL or search query)
- `/pause` - Pause the current song
- `/resume` - Resume playback
- `/skip` - Skip the current song
- `/stop` - Stop playback and clear the queue
- `/queue` - Display the current song queue
- `/nowplaying` - Show the currently playing song
- `/setup-player [channel-name]` - Create an interactive music player channel

## Prefix Commands (Legacy Support)

Traditional `!` prefix commands are still supported:

- `!play <song>` - Play a song
- `!pause` - Pause playback
- `!resume` - Resume playback
- `!skip` - Skip current song
- `!stop` - Stop and clear queue
- `!queue` - Show queue
- `!help` - Show available commands

## Interactive Music Player Channel

The bot can create a dedicated music player channel with interactive buttons:

1. Use `/setup-player` command (requires Administrator permission)
2. A new channel will be created with:
   - Real-time now playing information
   - Play/Pause button
   - Skip button
   - Stop button
   - Queue view button
3. The channel automatically updates when songs change

### Button Controls

- **⏸️ Pause / ▶️ Resume** - Toggle playback
- **⏭️ Skip** - Skip to the next song
- **⏹️ Stop** - Stop playback and clear the queue
- **📃 Queue** - View the current queue (ephemeral message)

## Setup Instructions

### 1. Create a Discord Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" and give it a name
3. Go to the "Bot" tab and click "Add Bot"
4. Under "Privileged Gateway Intents", enable:
   - **Message Content Intent** (Required)
   - Server Members Intent (optional)
5. Click "Reset Token" and copy your bot token (you'll need this later)
6. Go to the "OAuth2" > "URL Generator" tab
7. Select scopes:
   - `bot`
   - `applications.commands`
8. Select bot permissions:
   - Read Messages/View Channels
   - Send Messages
   - Manage Channels (for music player channel creation)
   - Embed Links
   - Connect
   - Speak
   - Use Voice Activity
9. Copy the generated URL and open it in your browser to invite the bot to your server

### 2. Deploy to Railway

#### Option A: Deploy from GitHub (Recommended)

1. Fork or clone this repository to your GitHub account
2. Rename `bot-enhanced.js` to `bot.js` (or update `package.json` main field)
3. Go to [Railway.app](https://railway.app) and sign up/login
4. Click "New Project" > "Deploy from GitHub repo"
5. Select your repository
6. Add environment variable:
   - Key: `DISCORD_TOKEN`
   - Value: Your bot token from Discord Developer Portal
7. Click "Deploy"

Railway will automatically:
- Detect the Node.js project
- Install dependencies
- Start the bot using `npm start`
- Register slash commands on startup

#### Option B: Deploy with Railway CLI

1. Install Railway CLI:
   ```bash
   npm i -g @railway/cli
   ```

2. Login to Railway:
   ```bash
   railway login
   ```

3. Initialize project:
   ```bash
   railway init
   ```

4. Add environment variable:
   ```bash
   railway variables set DISCORD_TOKEN=your_token_here
   ```

5. Deploy:
   ```bash
   railway up
   ```

### 3. Local Development (Optional)

If you want to test locally before deploying:

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd discord-music-bot
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file:
   ```bash
   cp .env.example .env
   ```

4. Edit `.env` and add your Discord token:
   ```
   DISCORD_TOKEN=your_actual_token_here
   ```

5. Rename `bot-enhanced.js` to `bot.js` or run directly:
   ```bash
   node bot-enhanced.js
   ```

## Usage Examples

### Using Slash Commands

```
/play never gonna give you up
/play https://www.youtube.com/watch?v=dQw4w9WgXcQ
/pause
/resume
/skip
/queue
/nowplaying
/stop
```

### Setting Up Music Player Channel

1. Type `/setup-player` in any channel
2. Optionally provide a custom channel name: `/setup-player channel-name:🎵-music`
3. The bot will create a new text channel with interactive controls
4. Only users with Administrator permission can create player channels

### Using Prefix Commands

```
!play despacito
!pause
!resume
!skip
!queue
!stop
!help
```

## Technical Details

### Dependencies

- **discord.js** (v14+) - Discord API wrapper with slash command support
- **@discordjs/voice** - Voice connection handling
- **@distube/ytdl-core** - YouTube video downloading
- **yt-search** - YouTube search functionality
- **ffmpeg-static** - Audio processing
- **libsodium-wrappers** - Voice encryption
- **opusscript** - Audio codec

### Features Breakdown

#### Slash Commands
- Modern Discord slash commands
- Automatic command registration on bot startup
- Deferred replies for search operations
- Ephemeral messages for button interactions

#### Interactive Player Channel
- Dedicated channel with locked permissions (users can't send messages)
- Real-time embed updates showing:
  - Current song title
  - Playback status (Playing/Paused/Stopped)
  - Queue size
  - Volume level
- Interactive buttons that update based on player state
- Buttons automatically enable/disable based on context

#### Music Playback
- High-quality audio streaming
- Automatic queue progression
- Pause/Resume functionality
- Error handling and recovery

### Requirements

- Node.js 16.x or higher
- FFmpeg (included via ffmpeg-static)
- Discord.js v14 or higher

## Troubleshooting

### Slash commands not appearing
- Wait a few minutes after bot starts (commands can take time to register)
- Try kicking and re-inviting the bot with the correct OAuth2 URL
- Ensure `applications.commands` scope is included in bot invite
- Check Railway logs for command registration errors

### Bot not responding to commands
- Verify the bot is online in your server
- Check if Message Content Intent is enabled
- Verify bot has proper permissions in the channel
- Check Railway logs for errors

### Music player channel issues
- Ensure you have Administrator permission
- Check if bot has "Manage Channels" permission
- Verify bot can send messages and embeds in the guild

### Voice connection issues
- Ensure the bot has "Connect" and "Speak" permissions
- Check if you're in a voice channel before using commands
- Try restarting the bot on Railway
- Verify the voice channel isn't full or restricted

### YouTube playback errors
- Some videos may be age-restricted or region-locked
- Try using a different video or search query
- Check Railway logs for specific error messages
- Ensure ytdl-core is up to date

### Button interactions not working
- Verify bot has "Use Application Commands" permission
- Check if the player message is from the current bot instance
- Try recreating the player channel with `/setup-player`

## Railway Configuration

Railway will automatically:
- Detect this as a Node.js project
- Run `npm install` to install dependencies
- Execute `npm start` to run the bot
- Keep the bot running 24/7
- Restart on crashes

To view logs:
1. Go to your Railway project dashboard
2. Click on your deployment
3. Go to the "Logs" tab
4. Look for "Slash commands registered successfully!" message

## Environment Variables

Required environment variables for Railway:

| Variable | Description |
|----------|-------------|
| `DISCORD_TOKEN` | Your Discord bot token from the Developer Portal |

## Advanced Configuration

### Customizing the Music Player

You can customize the player embed colors by modifying the `updatePlayerEmbed` function:
- Playing state: `#00ff00` (green)
- Paused state: `#ffaa00` (orange)
- Stopped state: `#0099ff` (blue)

### Queue Size Limits

Currently, there's no hard limit on queue size. To add one, modify the `handlePlay` function to check queue length before adding songs.

## License

ISC

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review Railway logs for error messages
3. Ensure all permissions are correctly set in Discord
4. Verify slash commands are registered (check logs)
5. Make sure Message Content Intent is enabled

## Contributing

Feel free to submit issues or pull requests!

## Notes

- Slash commands are the recommended way to interact with the bot
- Prefix commands are maintained for backward compatibility
- The music player channel provides the best user experience
- Only one player channel per server is supported
- Railway's free tier should be sufficient for small to medium Discord servers
- The bot will automatically rejoin voice if disconnected briefly

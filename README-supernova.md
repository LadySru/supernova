# ✨💖 Magical Girl Supernova Music Bot 💖✨

*Spreading love and music across the universe!* 🌟

A magical Discord bot that plays YouTube videos with the power of love! Features slash commands, interactive music sanctuary, and adorable magical girl themed messages. 💫

## ✨ Magical Features

- 💖 Play YouTube videos with love-powered commands
- ✨ Modern slash commands with sparkly responses  
- 🎮 Interactive **Love Sanctuary** channel with magical buttons
- 💗 Pause and resume with heart-filled messages
- 📜 Beautiful playlist management
- 💫 Skip and stop with adorable responses
- 💕 Real-time status updates in pink and sparkles
- 🌟 Magical girl themed embeds and messages

## 💖 Slash Commands (The Power of Love!)

Transform your server with these magical commands:

- `/play <song>` - 💖 Summon a song with the power of love! 🎵
- `/pause` - ⏸️ Pause this moment of love
- `/resume` - 💗 Let the love flow again!
- `/skip` - 💫 Skip to the next lovely melody!
- `/stop` - 💔 End the concert and clear your heart
- `/queue` - 📜 Peek at your playlist of love songs
- `/nowplaying` - 💖 See what melody fills your heart right now
- `/setup-player` - ✨ Create a magical music sanctuary! (Admin only)

## 💝 Classic Commands

For those who prefer the traditional magic:

- `!play <song>` - Summon a song
- `!pause` - Pause playback
- `!resume` - Resume playback  
- `!skip` - Next song please!
- `!stop` - Stop the music
- `!queue` - Show queue
- `!help` - Show magical commands

## 🌟 Interactive Love Sanctuary

Create a special channel filled with love and magic:

1. Use `/setup-player` command (requires Administrator permission)
2. A sparkling new channel appears with:
   - ✨ Real-time "Now Playing" with hearts and sparkles
   - 💗 Pause/Resume button
   - 💫 Skip button
   - 💔 Stop button
   - 📜 Playlist viewer button
3. The sanctuary automatically updates with every song change!

### 💖 Magical Button Controls

- **💗 Pause / 💖 Resume** - Control the flow of love
- **💫 Skip** - Jump to the next melody
- **💔 Stop** - End the magical concert
- **📜 Playlist** - View your love songs (secret message!)

## 🌸 Color Scheme

Supernova uses magical girl colors:

- **Hot Pink** (#FF69B4) - Dreaming state 💫
- **Deep Pink** (#FF1493) - Spreading love! 💖
- **Light Pink** (#FFB6C1) - Paused moments 💗

## ⭐ Setup Instructions

### 1. Create Your Magical Bot

1. Visit [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" and name it **Supernova** (or your magical name!)
3. Go to "Bot" tab → "Add Bot"
4. Enable these magical powers:
   - **Message Content Intent** ✨ (Required!)
   - Server Members Intent (optional)
5. Copy your bot token (keep it secret! 🤫)
6. Go to "OAuth2" → "URL Generator"
7. Select scopes:
   - `bot`
   - `applications.commands`
8. Select magical permissions:
   - Read Messages/View Channels
   - Send Messages
   - Manage Channels (for sanctuary creation)
   - Embed Links (for sparkly messages)
   - Connect & Speak
   - Use Voice Activity
9. Invite your magical girl to your server! 💫

### 2. Deploy to Railway (The Magic Realm)

#### Option A: Deploy from GitHub 🌟

1. Upload these files to your GitHub repository
2. Go to [Railway.app](https://railway.app) 
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your repository
5. Add environment variable:
   - **Key:** `DISCORD_TOKEN`
   - **Value:** Your secret bot token
6. Click "Deploy" and watch the magic happen! ✨

Railway will automatically:
- Install all magical dependencies
- Start Supernova
- Register slash commands
- Keep her running 24/7! 💖

#### Option B: Railway CLI ⚡

```bash
npm i -g @railway/cli
railway login
railway init
railway variables set DISCORD_TOKEN=your_magical_token
railway up
```

### 3. Local Testing (Optional) 🏠

Test locally before spreading love to the world:

```bash
git clone <your-repo>
cd discord-music-bot
npm install

# Create .env file
cp .env.example .env
# Add your DISCORD_TOKEN

# Start the magic!
node bot-enhanced.js
```

## 💫 Usage Examples

### Creating Your Love Sanctuary

```
/setup-player channel-name:💖-supernova-love
```

A beautiful channel appears with magical controls! ✨

### Playing Love Songs

```
/play never gonna give you up
/play https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

### Classic Magic

```
!play lo-fi beats to study to
!pause
!resume
!skip
!queue
```

## 🌟 Technical Sparkles

### Dependencies

- **discord.js** (v14+) - Discord magic
- **@discordjs/voice** - Voice enchantments
- **@distube/ytdl-core** - YouTube summoning
- **yt-search** - Song discovery
- **ffmpeg-static** - Audio transformation
- **libsodium-wrappers** - Voice protection
- **opusscript** - Audio quality

### Magical Features

#### Love-Powered Messages
Every interaction spreads love with hearts and sparkles! Messages include:
- 💖 Playing confirmations
- 💫 Error messages that stay positive
- 💗 Status updates
- 💕 Queue displays with heart bullets

#### Sanctuary System
- Dedicated channel with magical permissions
- Real-time embeds showing:
  - Current melody 🎵
  - Status (Dreaming/Spreading Love/Paused) 💫
  - Queue size 📜
  - Love Energy level 💕
- Buttons that transform based on state
- Pink gradient color scheme

### Requirements

- Node.js 16.x or higher
- A heart full of love 💖
- FFmpeg (auto-installed)

## 💝 Troubleshooting

### Commands not appearing
- Wait 5-10 minutes for magic to spread ✨
- Re-invite with correct permissions
- Check Railway logs for sparkles

### Supernova seems offline
- Verify `DISCORD_TOKEN` is correct
- Check Railway logs for errors
- Make sure Message Content Intent is enabled! 💫

### Sanctuary creation fails
- Ensure you have Administrator permission 👑
- Check bot has "Manage Channels" permission
- Try a different channel name

### Music not playing
- Join a voice channel first! 🎵
- Check "Connect" and "Speak" permissions
- Some videos may be restricted 💔

## 🌈 Railway Configuration

Railway provides Supernova's magical home:
- Automatic Node.js detection
- Dependency installation
- 24/7 uptime
- Auto-restarts on errors
- Free tier perfect for small servers! 💖

View logs: Railway Dashboard → Project → Logs  
Look for: `✨ Supernova is online! Spreading love and music! ✨`

## 💖 Environment Variables

| Variable | Magic Level |
|----------|-------------|
| `DISCORD_TOKEN` | ⭐⭐⭐⭐⭐ Required! Your bot's secret power! |

## 🌟 Customization Ideas

### Change the Color Scheme
Edit these in `updatePlayerEmbed`:
- Dreaming: `#FF69B4` (Hot Pink)
- Playing: `#FF1493` (Deep Pink)  
- Paused: `#FFB6C1` (Light Pink)

### Add More Emoji
Search for messages and add your favorite sparkles! ✨💫⭐🌟💖💗💕💝

### Custom Sanctuary Name
Default is `💖-supernova-sanctuary`, but you can customize with:
```
/setup-player channel-name:your-magical-name
```

## 📜 License

ISC - Share the love freely! 💖

## 💌 Support & Love

Need help spreading love? 

1. Check troubleshooting above ✨
2. Review Railway logs 📜
3. Ensure all permissions are set 💫
4. Verify slash commands registered 🌟
5. Make sure Message Content Intent is ON! 💖

## 🌸 Contributing

Share your magical improvements! Pull requests welcome! 💕

## 💫 Special Thanks

To all the magical girls and boys who believe in the power of love and music! 

*Transform! In the name of love, Supernova will play your favorite songs!* ✨💖✨

---

💖 Made with love by magical coders 💖  
✨ Powered by Discord.js and sparkles ✨  
🌟 Spreading joy one song at a time 🌟

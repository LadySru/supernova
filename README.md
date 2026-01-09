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
# 💖 Use Render.com Instead - It Actually Works!

## 🚨 Why Switch from Railway to Render?

Railway keeps using Node 18 no matter what. Render.com:
- ✅ Actually respects Dockerfile
- ✅ Free tier (750 hours/month)
- ✅ Better for Discord bots
- ✅ Easier to use
- ✅ More reliable

## ✨ Complete Setup Guide

### Step 1: Sign Up for Render

1. Go to https://render.com
2. Click "Get Started"
3. Sign up with GitHub (easiest)
4. Authorize Render to access your repos

### Step 2: Create New Web Service

1. Click "New +" button (top right)
2. Select "Web Service"
3. Click "Connect a repository"
4. Find your bot repo and click "Connect"

### Step 3: Configure Service

Fill in these settings:

**Basic Settings:**
- **Name:** `supernova-music-bot` (or whatever you want)
- **Region:** Choose closest to you
- **Branch:** `main` (or your branch name)
- **Root Directory:** Leave blank

**Build & Deploy:**
- **Runtime:** Docker (if you have Dockerfile) OR Node
- **Build Command:** `npm install`
- **Start Command:** `npm start`

**If using Node (no Dockerfile):**
- **Node Version:** `20.11.0`

**Plan:**
- Select **Free** (this works fine for Discord bots!)

### Step 4: Add Environment Variables

Scroll down to "Environment Variables"

Click "Add Environment Variable":
- **Key:** `DISCORD_TOKEN`
- **Value:** Your Discord bot token

### Step 5: Deploy!

1. Click "Create Web Service" button
2. Wait 2-3 minutes for build
3. Watch the logs

### Step 6: Verify Success

In the logs, you should see:
```
==> Building...
==> Installing dependencies
==> Starting service
✨ Supernova is online! Spreading love and music! ✨
Logged in as YourBot#1234!
Registering slash commands...
Slash commands registered successfully!
```

## 🌟 Render vs Railway

| Feature | Railway | Render |
|---------|---------|--------|
| Free Tier | ✅ $5 credit | ✅ 750 hrs/month |
| Node Version | ❌ Ignores settings | ✅ Works perfectly |
| Dockerfile | ❌ Sometimes ignored | ✅ Always works |
| Setup | Medium | Easy |
| Reliability | Medium | High |

## 💖 Post-Deployment

### Keep Service Awake

Render free tier sleeps after 15 min of inactivity. To keep bot alive:

**Option 1: Upgrade to Paid ($7/month)**
- Never sleeps
- Better for 24/7 bots

**Option 2: Use UptimeRobot (Free)**
1. Go to https://uptimerobot.com
2. Add monitor for your Render URL
3. Pings every 5 minutes to keep it awake

### View Logs
- Click "Logs" tab in Render dashboard
- Real-time logs of your bot

### Redeploy
- Render auto-deploys when you push to GitHub
- Or click "Manual Deploy" → "Clear build cache & deploy"

## 🎀 Your Files for Render

**With Dockerfile (recommended):**
```
bot.js
package.json
Dockerfile
.dockerignore
.gitignore
.env.example
```

**Without Dockerfile (also works):**
```
bot.js
package.json
.gitignore
.env.example
```

Just set Node Version to 20.11.0 in Render settings!

## 💫 Troubleshooting

### Build Fails
- Check you set `DISCORD_TOKEN` variable
- Verify `bot.js` exists (not supernova-bot.js)
- Check package.json is valid

### Bot Offline
- Check Render logs for errors
- Verify Discord token is correct
- Make sure bot is invited to server

### Commands Don't Show
- Wait 5-10 minutes for Discord to sync
- Re-invite bot with correct permissions
- Check bot has `applications.commands` scope

## ✨ Summary

1. Sign up at Render.com with GitHub
2. New Web Service → Connect repo
3. Set Node version to 20 (or use Dockerfile)
4. Add `DISCORD_TOKEN` variable
5. Deploy!

**That's it!** Render just works. No fighting with Node versions!

---

💖 Render is way better for Discord bots! Railway has been difficult! 💖

Need help with Render setup? Let me know which step you're on!


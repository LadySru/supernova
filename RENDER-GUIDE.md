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

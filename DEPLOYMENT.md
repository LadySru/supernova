# Quick Deployment Guide - Enhanced Music Bot

## Pre-Deployment Checklist

✅ Discord Bot Created  
✅ Bot Token Copied  
✅ Message Content Intent Enabled  
✅ Bot Invited with Correct Permissions

## File Setup for Railway

Before deploying, you have two options:

### Option 1: Rename the enhanced file (Recommended)

```bash
# Rename bot-enhanced.js to bot.js
mv bot-enhanced.js bot.js
```

Your `package.json` already points to `bot.js` as the main file.

### Option 2: Update package.json

Keep `bot-enhanced.js` and update `package.json`:

```json
{
  "main": "bot-enhanced.js",
  "scripts": {
    "start": "node bot-enhanced.js"
  }
}
```

## Railway Deployment Steps

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit - Discord Music Bot"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

### 2. Deploy on Railway

1. Go to https://railway.app
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Choose your repository
5. Railway will auto-detect Node.js

### 3. Add Environment Variables

In Railway dashboard:
- Click on your project
- Go to "Variables" tab
- Add new variable:
  - **Key:** `DISCORD_TOKEN`
  - **Value:** Your bot token from Discord Developer Portal
- Click "Add"

### 4. Deploy

Railway will automatically:
- Install dependencies (`npm install`)
- Start the bot (`npm start`)
- Register slash commands

Watch the logs for:
```
Logged in as YourBot#1234!
Registering slash commands...
Slash commands registered successfully!
```

## Post-Deployment

### Test Slash Commands

In your Discord server:
1. Type `/` in any channel
2. You should see your bot's commands appear
3. Try `/play never gonna give you up`

### Create Music Player Channel

1. Type `/setup-player` in any channel
2. Bot will create a dedicated music player channel
3. The channel will have interactive buttons

## Common Issues

### Commands not showing up
- **Wait 5-10 minutes** - Slash commands can take time to propagate
- Re-invite the bot with the OAuth2 URL including `applications.commands` scope
- Check Railway logs for errors

### Bot offline on Railway
- Check "Logs" tab in Railway
- Verify `DISCORD_TOKEN` is set correctly
- Ensure no syntax errors in code

### Buttons not responding
- Verify bot has "Use Application Commands" permission
- Recreate the player channel with `/setup-player`

## Railway Free Tier Notes

The free tier includes:
- 500 hours of usage per month
- $5 credit per month
- Automatic scaling

This is sufficient for most small to medium Discord servers.

## Monitoring Your Bot

### View Logs
Railway Dashboard → Your Project → Logs

### Check Status
Railway Dashboard → Your Project → Deployments

### Update Code
1. Push changes to GitHub
2. Railway auto-deploys new changes

## Next Steps

1. ✅ Test all slash commands
2. ✅ Create music player channel with `/setup-player`
3. ✅ Test button interactions
4. ✅ Invite bot to your server
5. ✅ Share with friends!

## Support Commands Reference

```
/play <song>           - Play music
/pause                 - Pause playback
/resume                - Resume playback
/skip                  - Skip song
/stop                  - Stop and clear queue
/queue                 - Show queue
/nowplaying            - Current song info
/setup-player          - Create player channel
```

## Need Help?

- Check Railway logs for errors
- Verify all permissions are set
- Ensure Message Content Intent is enabled
- Make sure bot has Manage Channels permission for `/setup-player`

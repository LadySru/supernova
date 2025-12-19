# 🚀 GitHub → Railway Deployment Guide

## 📦 **COMPLETE FILE LIST FOR GITHUB:**

Upload these files to GitHub (9 files total):

### ✅ Core Bot Files:
1. **love_magic_bot.py** - Main bot code
2. **requirements.txt** - Python dependencies

### ✅ Railway Configuration:
3. **Procfile** - Tells Railway this is a worker bot
4. **nixpacks.toml** - Installs Python + FFmpeg
5. **railway.toml** - Railway deployment settings

### ✅ Security:
6. **.gitignore** - Prevents uploading sensitive files
7. **.env.example** - Template for environment variables

### ✅ Documentation:
8. **README.md** - Bot documentation
9. **DEPLOYMENT_GUIDE.md** - This file (optional)

### ❌ NEVER UPLOAD:
- **.env** - Contains your Discord token!

---

## 🎯 **STEP-BY-STEP DEPLOYMENT:**

### **STEP 1: Create GitHub Repository**

1. Go to https://github.com
2. Click **+** (top right) → **New repository**
3. Name: `magical-love-discord-bot`
4. Visibility: **Private** (recommended)
5. ✅ Check "Add a README file"
6. Click **Create repository**

---

### **STEP 2: Upload Files to GitHub**

**Method A - GitHub Website (Easiest):**

1. In your repository, click **Add file** → **Upload files**
2. Drag and drop these 9 files:
   - love_magic_bot.py
   - requirements.txt
   - Procfile
   - nixpacks.toml
   - railway.toml
   - .gitignore
   - .env.example
   - README.md
   - DEPLOYMENT_GUIDE.md (optional)
3. Scroll down and click **Commit changes**
4. Wait for upload to complete

**Method B - Git Command Line:**

```bash
# Navigate to your bot folder
cd /path/to/your/bot/folder

# Initialize git
git init

# Add all files (gitignore will exclude .env automatically)
git add .

# Commit
git commit -m "Initial commit - Magical Love Discord Bot 💖"

# Add your GitHub repository as remote
# Replace YOUR_USERNAME and YOUR_REPO with your actual values
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git

# Push to GitHub
git branch -M main
git push -u origin main
```

---

### **STEP 3: Deploy on Railway**

1. Go to https://railway.app
2. Click **Login** → Sign in with GitHub
3. Authorize Railway to access your repositories
4. Click **New Project**
5. Select **Deploy from GitHub repo**
6. Find and select your `magical-love-discord-bot` repository
7. Click **Deploy**

Railway will automatically:
- Detect it's a Python project
- Install Python 3.10
- Install FFmpeg (from nixpacks.toml)
- Install dependencies (from requirements.txt)
- Start your bot (from Procfile)

---

### **STEP 4: Add Environment Variables**

**CRITICAL - Your bot won't start without this!**

1. In Railway dashboard, click on your deployed service
2. Go to **Variables** tab
3. Click **+ New Variable**
4. Add your Discord token:
   - **Variable:** `DISCORD_TOKEN`
   - **Value:** Your actual Discord token
   
   Example:
   ```
   DISCORD_TOKEN
   MTQ1MTAzMjg2MzI1NTU2NDM3OA.GATQAD.HqmNapEtpgS1_fkKsRQldbzHXeL8ow40vy-CWQ
   ```
5. Click **Add**

Railway will automatically redeploy with the new variable.

---

### **STEP 5: Verify Deployment**

1. Go to **Deployments** tab
2. Click on the latest deployment
3. Check the **Logs**

**Success looks like:**
```
✨ [BotName] has awakened with the power of magical love! 💖
💕 Synced 11 slash commands!
```

4. Check Discord - your bot should be **Online** (green status)
5. Type `/help` in Discord to test

---

## ✅ **VERIFICATION CHECKLIST:**

After deployment, verify:

- [ ] All files uploaded to GitHub (except .env)
- [ ] Railway project created and connected to GitHub
- [ ] DISCORD_TOKEN added to Railway Variables
- [ ] Deployment shows "Success" in Railway
- [ ] Logs show bot started successfully
- [ ] Bot shows as Online in Discord
- [ ] Slash commands work (`/help`, `/play`, etc.)

---

## 🔧 **RAILWAY SETTINGS (If Needed):**

If deployment fails, check these settings:

### In Railway → Settings:

**Start Command:**
```
python love_magic_bot.py
```

**Build Command:** (usually auto-detected, but if needed)
```
pip install -r requirements.txt
```

**Watch Paths:** (leave default)
```
**
```

**Root Directory:**
```
/
```

---

## 🐛 **TROUBLESHOOTING:**

### **Error: "Could not determine how to build"**
- Make sure `requirements.txt` is in the root of your repository
- Make sure `nixpacks.toml` is uploaded
- Check that files aren't in a subfolder

### **Error: "No Discord token found"**
- Add `DISCORD_TOKEN` in Railway Variables
- Make sure there are no spaces or quotes around the token
- Redeploy after adding the variable

### **Error: "FFmpeg not found"**
- Make sure `nixpacks.toml` is uploaded correctly
- Redeploy the service
- Check build logs for FFmpeg installation

### **Bot is offline in Discord:**
- Check Railway logs for errors
- Verify Discord token is correct
- Make sure bot has proper intents enabled in Discord Developer Portal
- Check that bot is invited to your server with correct permissions

### **Commands don't appear:**
- Wait 1-5 minutes for Discord to sync
- Make sure bot was invited with `applications.commands` scope
- Try restarting Discord app
- Check logs to confirm commands synced

---

## 🔄 **UPDATING YOUR BOT:**

When you make changes to your code:

### **Option 1 - GitHub Website:**
1. Go to your GitHub repository
2. Click on the file you want to edit
3. Click the pencil icon (Edit)
4. Make your changes
5. Click **Commit changes**
6. Railway auto-deploys! ✨

### **Option 2 - Git Command Line:**
```bash
# Make your changes to files
# Then:

git add .
git commit -m "Update bot with new features"
git push origin main

# Railway automatically detects the push and redeploys!
```

### **Option 3 - Manual Redeploy:**
1. In Railway, go to Deployments
2. Click three dots on latest deployment
3. Click **Redeploy**

---

## 💰 **RAILWAY PRICING:**

- **Free Tier:** $5 in credits per month
- **Bot Usage:** ~$3-4 per month for a small bot
- **Execution Time:** First 500 hours free, then $0.000231/min
- **Perfect for:** Personal Discord bots

If you run out of credits, add a payment method or the bot will stop until next month.

---

## 🎉 **YOU'RE DONE!**

Your bot is now:
- ✅ Live 24/7 on Railway
- ✅ Auto-deploys when you push to GitHub
- ✅ Automatically restarts if it crashes
- ✅ Running in the cloud (no need to keep your computer on!)

---

## 📱 **NEXT STEPS:**

Test your bot:
```
/help                    → View all commands
/setup_player           → Create music control panel
/play never gonna give you up  → Test music (join voice first)
/remind 1 Test!         → Test reminders
```

Enjoy your magical love bot! 💖✨

---

## 🆘 **NEED HELP?**

Common issues and solutions are in the Troubleshooting section above.

If you're still stuck:
1. Check Railway logs for specific error messages
2. Verify all files are uploaded to GitHub
3. Make sure DISCORD_TOKEN is set in Railway Variables
4. Check Discord Developer Portal for proper bot configuration

Your bot should be running smoothly on Railway now! 🚂💕

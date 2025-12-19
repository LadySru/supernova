# ⚡ QUICK START - GitHub → Railway

## 📋 **30-SECOND CHECKLIST:**

### **1. GitHub (5 min):**
- [ ] Create new repository on GitHub
- [ ] Upload these 7 files:
  - ✅ love_magic_bot.py
  - ✅ requirements.txt
  - ✅ Procfile
  - ✅ nixpacks.toml
  - ✅ railway.toml
  - ✅ .gitignore
  - ✅ .env.example
- [ ] **DO NOT upload .env!**

### **2. Railway (3 min):**
- [ ] Login to https://railway.app with GitHub
- [ ] New Project → Deploy from GitHub repo
- [ ] Select your repository
- [ ] Add Variable: `DISCORD_TOKEN` = your token
- [ ] Wait for deployment (2-3 minutes)

### **3. Verify (1 min):**
- [ ] Check logs for: `✨ has awakened with the power of magical love! 💖`
- [ ] Bot is online in Discord
- [ ] Test: `/help` command works

---

## 🎯 **EXACT FILES TO UPLOAD:**

Copy these exact files to GitHub:

```
magical-love-discord-bot/
├── love_magic_bot.py       ← Main bot code
├── requirements.txt        ← Dependencies
├── Procfile               ← "worker: python love_magic_bot.py"
├── nixpacks.toml          ← Python + FFmpeg config
├── railway.toml           ← Railway settings
├── .gitignore             ← Security
└── .env.example           ← Template (safe to share)
```

**DO NOT UPLOAD:** `.env` (contains your token!)

---

## 🔑 **Your Discord Token:**

In Railway Variables, add:
```
DISCORD_TOKEN = MTQ1MTAzMjg2MzI1NTU2NDM3OA.GATQAD.HqmNapEtpgS1_fkKsRQldbzHXeL8ow40vy-CWQ
```

---

## ✅ **Success Indicators:**

Railway Logs should show:
```
Building...
Installing Python 3.10...
Installing FFmpeg...
Installing requirements...
Starting bot...
✨ [BotName] has awakened with the power of magical love! 💖
💕 Synced 11 slash commands!
```

Discord:
- Bot shows green "Online" status
- Typing `/` shows your bot's commands

---

## 🆘 **Quick Fixes:**

**Bot offline?**
→ Add DISCORD_TOKEN to Railway Variables

**"Could not build"?**
→ Make sure requirements.txt is in root folder

**"FFmpeg not found"?**
→ Upload nixpacks.toml and redeploy

**Commands not showing?**
→ Wait 2-5 minutes, restart Discord app

---

## 🎉 **Done!**

Your bot is now live 24/7! See DEPLOYMENT_GUIDE.md for full details.

Test: `/play never gonna give you up` 💕

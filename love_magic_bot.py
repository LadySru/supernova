import discord
from discord import app_commands
from discord.ext import commands, tasks
from discord.ui import Button, View
import yt_dlp
import asyncio
from datetime import datetime, timedelta
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Bot setup with magical love theme
intents = discord.Intents.default()
intents.message_content = True
intents.voice_states = True

bot = commands.Bot(command_prefix='/', intents=intents, help_command=None)
tree = bot.tree

# Store reminders
reminders = []

# YouTube downloader options
ytdl_format_options = {
    'format': 'bestaudio/best',
    'outtmpl': '%(extractor)s-%(id)s-%(title)s.%(ext)s',
    'restrictfilenames': True,
    'noplaylist': True,
    'nocheckcertificate': True,
    'ignoreerrors': False,
    'logtostderr': False,
    'quiet': True,
    'no_warnings': True,
    'default_search': 'auto',
    'source_address': '0.0.0.0',
}

ffmpeg_options = {
    'options': '-vn'
}

ytdl = yt_dlp.YoutubeDL(ytdl_format_options)

class YTDLSource(discord.PCMVolumeTransformer):
    def __init__(self, source, *, data, volume=0.5):
        super().__init__(source, volume)
        self.data = data
        self.title = data.get('title')
        self.url = data.get('url')

    @classmethod
    async def from_url(cls, url, *, loop=None, stream=False):
        loop = loop or asyncio.get_event_loop()
        data = await loop.run_in_executor(None, lambda: ytdl.extract_info(url, download=not stream))

        if 'entries' in data:
            data = data['entries'][0]

        filename = data['url'] if stream else ytdl.prepare_filename(data)
        return cls(discord.FFmpegPCMAudio(filename, **ffmpeg_options), data=data)

# Music queue for each server
music_queues = {}

# Music player panels for each server
music_panels = {}

class MusicPlayerView(View):
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(label='⏸️ Pause', style=discord.ButtonStyle.primary, custom_id='pause_button')
    async def pause_button(self, interaction: discord.Interaction, button: Button):
        if interaction.guild.voice_client and interaction.guild.voice_client.is_playing():
            interaction.guild.voice_client.pause()
            await interaction.response.send_message("⏸️ Love is patient... The music awaits! 💕", ephemeral=True)
        else:
            await interaction.response.send_message("💔 There's no music playing right now!", ephemeral=True)
    
    @discord.ui.button(label='▶️ Resume', style=discord.ButtonStyle.success, custom_id='resume_button')
    async def resume_button(self, interaction: discord.Interaction, button: Button):
        if interaction.guild.voice_client and interaction.guild.voice_client.is_paused():
            interaction.guild.voice_client.resume()
            await interaction.response.send_message("▶️ The magic continues! 💖", ephemeral=True)
        else:
            await interaction.response.send_message("💔 The music isn't paused!", ephemeral=True)
    
    @discord.ui.button(label='⏭️ Skip', style=discord.ButtonStyle.secondary, custom_id='skip_button')
    async def skip_button(self, interaction: discord.Interaction, button: Button):
        if interaction.guild.voice_client and interaction.guild.voice_client.is_playing():
            interaction.guild.voice_client.stop()
            await interaction.response.send_message("⏭️ Skipping to the next enchanted melody! 💫", ephemeral=True)
        else:
            await interaction.response.send_message("💔 There's nothing to skip!", ephemeral=True)
    
    @discord.ui.button(label='📋 Queue', style=discord.ButtonStyle.secondary, custom_id='queue_button')
    async def queue_button(self, interaction: discord.Interaction, button: Button):
        guild_id = interaction.guild.id
        
        if guild_id not in music_queues or not music_queues[guild_id]:
            await interaction.response.send_message("💔 The playlist is empty! Add some love songs with /play", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="💝 Magical Love Playlist",
            color=discord.Color.pink()
        )
        
        queue_text = ""
        for i, player in enumerate(music_queues[guild_id][:10], 1):  # Show first 10
            queue_text += f"{i}. **{player.title}**\n"
        
        if len(music_queues[guild_id]) > 10:
            queue_text += f"\n...and {len(music_queues[guild_id]) - 10} more songs!"
        
        embed.description = queue_text
        embed.set_footer(text="✨ Songs queued with love ✨")
        await interaction.response.send_message(embed=embed, ephemeral=True)
    
    @discord.ui.button(label='🔊 Volume Up', style=discord.ButtonStyle.secondary, custom_id='volume_up_button')
    async def volume_up_button(self, interaction: discord.Interaction, button: Button):
        if interaction.guild.voice_client and interaction.guild.voice_client.source:
            current_volume = int(interaction.guild.voice_client.source.volume * 100)
            new_volume = min(100, current_volume + 10)
            interaction.guild.voice_client.source.volume = new_volume / 100
            await interaction.response.send_message(f"🔊 Volume increased to {new_volume}%! 💕", ephemeral=True)
        else:
            await interaction.response.send_message("💔 No music is playing!", ephemeral=True)
    
    @discord.ui.button(label='🔉 Volume Down', style=discord.ButtonStyle.secondary, custom_id='volume_down_button')
    async def volume_down_button(self, interaction: discord.Interaction, button: Button):
        if interaction.guild.voice_client and interaction.guild.voice_client.source:
            current_volume = int(interaction.guild.voice_client.source.volume * 100)
            new_volume = max(0, current_volume - 10)
            interaction.guild.voice_client.source.volume = new_volume / 100
            await interaction.response.send_message(f"🔉 Volume decreased to {new_volume}%! 💕", ephemeral=True)
        else:
            await interaction.response.send_message("💔 No music is playing!", ephemeral=True)
    
    @discord.ui.button(label='⏹️ Stop', style=discord.ButtonStyle.danger, custom_id='stop_button')
    async def stop_button(self, interaction: discord.Interaction, button: Button):
        guild_id = interaction.guild.id
        if guild_id in music_queues:
            music_queues[guild_id].clear()
        
        if interaction.guild.voice_client:
            await interaction.guild.voice_client.disconnect()
            await interaction.response.send_message("👋 Goodbye, lovely soul! The magic will return when you call! 💖✨", ephemeral=True)
        else:
            await interaction.response.send_message("💔 I'm not in a voice channel!", ephemeral=True)

@bot.event
async def on_ready():
    print(f'✨ {bot.user} has awakened with the power of magical love! 💖')
    
    # Add persistent view
    bot.add_view(MusicPlayerView())
    
    try:
        synced = await tree.sync()
        print(f'💕 Synced {len(synced)} slash commands!')
    except Exception as e:
        print(f'Failed to sync commands: {e}')
    
    check_reminders.start()
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.listening, 
        name="love songs 💕 | /help"
    ))

@tree.command(name='help', description='Shows all magical commands')
async def help_command(interaction: discord.Interaction):
    embed = discord.Embed(
        title="💖 Magical Love Bot Commands 💖",
        description="Spread love and magic with these enchanted commands!",
        color=discord.Color.pink()
    )
    
    embed.add_field(
        name="🎵 Music Commands",
        value=(
            "**/play [url/search]** - Play a love song from YouTube\n"
            "**/pause** - Pause the current melody\n"
            "**/resume** - Resume the magic\n"
            "**/skip** - Skip to the next song\n"
            "**/queue** - View the enchanted playlist\n"
            "**/stop** - Stop playing and disconnect\n"
            "**/volume [0-100]** - Adjust the volume\n"
            "**/setup_player** - Create a music player panel with buttons!"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⏰ Reminder Commands",
        value=(
            "**/remind [minutes] [message]** - Set a magical reminder\n"
            "**/reminders** - View all your reminders"
        ),
        inline=False
    )
    
    embed.set_footer(text="Made with magical love 💕✨")
    await interaction.response.send_message(embed=embed)

@tree.command(name='setup_player', description='Creates a music player control panel in this channel')
@app_commands.checks.has_permissions(manage_channels=True)
async def setup_player(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🎵 Magical Love Music Player 💖",
        description="Control the music with these magical buttons!\n\nUse **/play [song]** to add songs to the queue.",
        color=discord.Color.pink()
    )
    embed.add_field(
        name="Now Playing",
        value="*Nothing playing yet...*",
        inline=False
    )
    embed.add_field(
        name="Queue",
        value="*Queue is empty*",
        inline=False
    )
    embed.set_footer(text="✨ Made with magical love ✨")
    
    view = MusicPlayerView()
    message = await interaction.channel.send(embed=embed, view=view)
    
    # Store the panel message for updates
    music_panels[interaction.guild.id] = {
        'channel_id': interaction.channel.id,
        'message_id': message.id
    }
    
    await interaction.response.send_message("💖 Music player panel created! Use the buttons to control playback!", ephemeral=True)

@tree.command(name='play', description='Plays a song from YouTube')
@app_commands.describe(query='YouTube URL or search term')
async def play(interaction: discord.Interaction, query: str):
    if not interaction.user.voice:
        await interaction.response.send_message("💔 You need to be in a voice channel to summon love songs!")
        return

    channel = interaction.user.voice.channel
    
    await interaction.response.defer()
    
    if interaction.guild.voice_client is None:
        await channel.connect()
    elif interaction.guild.voice_client.channel != channel:
        await interaction.guild.voice_client.move_to(channel)

    try:
        player = await YTDLSource.from_url(query, loop=bot.loop, stream=True)
        
        guild_id = interaction.guild.id
        if guild_id not in music_queues:
            music_queues[guild_id] = []
        
        music_queues[guild_id].append(player)
        
        if not interaction.guild.voice_client.is_playing():
            await play_next(interaction)
        else:
            embed = discord.Embed(
                title="💝 Added to Queue",
                description=f"**{player.title}** has been added to the magical playlist!",
                color=discord.Color.pink()
            )
            await interaction.followup.send(embed=embed)
            
            # Update the music panel
            await update_music_panel(guild_id)
            
    except Exception as e:
        await interaction.followup.send(f"💔 Oops! The magic failed: {str(e)}")

async def play_next(interaction):
    guild_id = interaction.guild.id
    
    if guild_id in music_queues and music_queues[guild_id]:
        player = music_queues[guild_id].pop(0)
        
        def after_playing(error):
            if error:
                print(f'Error: {error}')
            
            coro = play_next(interaction)
            fut = asyncio.run_coroutine_threadsafe(coro, bot.loop)
            try:
                fut.result()
            except:
                pass
        
        interaction.guild.voice_client.play(player, after=after_playing)
        
        embed = discord.Embed(
            title="🎶 Now Playing with Love",
            description=f"**{player.title}**",
            color=discord.Color.pink()
        )
        embed.set_footer(text="Let the magic flow through you 💕✨")
        
        # Send as followup if already deferred, otherwise send normally
        try:
            await interaction.followup.send(embed=embed)
        except:
            channel = interaction.channel
            await channel.send(embed=embed)
        
        # Update music player panel if it exists
        await update_music_panel(guild_id, player.title)
        
    elif interaction.guild.voice_client and not interaction.guild.voice_client.is_playing():
        # Update panel to show nothing playing
        await update_music_panel(guild_id, None)
        
        await asyncio.sleep(180)
        if interaction.guild.voice_client and not interaction.guild.voice_client.is_playing():
            await interaction.guild.voice_client.disconnect()
            await interaction.channel.send("💫 The magic fades... Until next time, lovely soul! 💖")

async def update_music_panel(guild_id, now_playing_title=None):
    """Update the music player panel with current status"""
    if guild_id not in music_panels:
        return
    
    try:
        channel = bot.get_channel(music_panels[guild_id]['channel_id'])
        message = await channel.fetch_message(music_panels[guild_id]['message_id'])
        
        embed = discord.Embed(
            title="🎵 Magical Love Music Player 💖",
            description="Control the music with these magical buttons!\n\nUse **/play [song]** to add songs to the queue.",
            color=discord.Color.pink()
        )
        
        # Now Playing
        if now_playing_title:
            embed.add_field(
                name="Now Playing",
                value=f"🎵 **{now_playing_title}**",
                inline=False
            )
        else:
            embed.add_field(
                name="Now Playing",
                value="*Nothing playing yet...*",
                inline=False
            )
        
        # Queue
        if guild_id in music_queues and music_queues[guild_id]:
            queue_text = ""
            for i, player in enumerate(music_queues[guild_id][:5], 1):
                queue_text += f"{i}. {player.title}\n"
            if len(music_queues[guild_id]) > 5:
                queue_text += f"*...and {len(music_queues[guild_id]) - 5} more songs*"
            embed.add_field(
                name="Queue",
                value=queue_text,
                inline=False
            )
        else:
            embed.add_field(
                name="Queue",
                value="*Queue is empty*",
                inline=False
            )
        
        embed.set_footer(text="✨ Made with magical love ✨")
        
        await message.edit(embed=embed)
    except Exception as e:
        print(f"Failed to update music panel: {e}")

@tree.command(name='pause', description='Pauses the current song')
async def pause(interaction: discord.Interaction):
    if interaction.guild.voice_client and interaction.guild.voice_client.is_playing():
        interaction.guild.voice_client.pause()
        await interaction.response.send_message("⏸️ Love is patient... The music awaits! 💕")
    else:
        await interaction.response.send_message("💔 There's no music playing right now!")

@tree.command(name='resume', description='Resumes the paused song')
async def resume(interaction: discord.Interaction):
    if interaction.guild.voice_client and interaction.guild.voice_client.is_paused():
        interaction.guild.voice_client.resume()
        await interaction.response.send_message("▶️ The magic continues! 💖")
    else:
        await interaction.response.send_message("💔 The music isn't paused!")

@tree.command(name='skip', description='Skips the current song')
async def skip(interaction: discord.Interaction):
    if interaction.guild.voice_client and interaction.guild.voice_client.is_playing():
        interaction.guild.voice_client.stop()
        await interaction.response.send_message("⏭️ Skipping to the next enchanted melody! 💫")
    else:
        await interaction.response.send_message("💔 There's nothing to skip!")

@tree.command(name='queue', description='Shows the music queue')
async def queue(interaction: discord.Interaction):
    guild_id = interaction.guild.id
    
    if guild_id not in music_queues or not music_queues[guild_id]:
        await interaction.response.send_message("💔 The playlist is empty! Add some love songs with /play")
        return
    
    embed = discord.Embed(
        title="💝 Magical Love Playlist",
        color=discord.Color.pink()
    )
    
    queue_text = ""
    for i, player in enumerate(music_queues[guild_id], 1):
        queue_text += f"{i}. **{player.title}**\n"
    
    embed.description = queue_text
    embed.set_footer(text="✨ Songs queued with love ✨")
    await interaction.response.send_message(embed=embed)

@tree.command(name='stop', description='Stops playing and disconnects')
async def stop(interaction: discord.Interaction):
    guild_id = interaction.guild.id
    if guild_id in music_queues:
        music_queues[guild_id].clear()
    
    if interaction.guild.voice_client:
        await interaction.guild.voice_client.disconnect()
        await interaction.response.send_message("👋 Goodbye, lovely soul! The magic will return when you call! 💖✨")
    else:
        await interaction.response.send_message("💔 I'm not in a voice channel!")

@tree.command(name='volume', description='Changes the volume (0-100)')
@app_commands.describe(volume='Volume level between 0 and 100')
async def volume(interaction: discord.Interaction, volume: int):
    if interaction.guild.voice_client is None:
        return await interaction.response.send_message("💔 I'm not connected to a voice channel!")

    if 0 <= volume <= 100:
        interaction.guild.voice_client.source.volume = volume / 100
        await interaction.response.send_message(f"🔊 Volume set to {volume}% with love! 💕")
    else:
        await interaction.response.send_message("💔 Please choose a volume between 0 and 100!")

@tree.command(name='remind', description='Set a magical reminder')
@app_commands.describe(
    minutes='Number of minutes until reminder',
    message='The reminder message'
)
async def remind(interaction: discord.Interaction, minutes: int, message: str):
    if minutes <= 0:
        await interaction.response.send_message("💔 Please set a positive number of minutes!")
        return
    
    reminder_time = datetime.now() + timedelta(minutes=minutes)
    reminder = {
        'user_id': interaction.user.id,
        'channel_id': interaction.channel.id,
        'message': message,
        'time': reminder_time.isoformat()
    }
    
    reminders.append(reminder)
    
    embed = discord.Embed(
        title="⏰ Reminder Set with Love!",
        description=f"I'll remind you in **{minutes} minute{'s' if minutes != 1 else ''}**!",
        color=discord.Color.pink()
    )
    embed.add_field(name="Message", value=message, inline=False)
    embed.set_footer(text="The magic will remember for you 💕✨")
    
    await interaction.response.send_message(embed=embed)

@tree.command(name='reminders', description='View all your active reminders')
async def view_reminders(interaction: discord.Interaction):
    user_reminders = [r for r in reminders if r['user_id'] == interaction.user.id]
    
    if not user_reminders:
        await interaction.response.send_message("💫 You have no active reminders! Set one with /remind")
        return
    
    embed = discord.Embed(
        title="⏰ Your Magical Reminders",
        color=discord.Color.pink()
    )
    
    for i, reminder in enumerate(user_reminders, 1):
        time_left = datetime.fromisoformat(reminder['time']) - datetime.now()
        minutes_left = int(time_left.total_seconds() / 60)
        
        embed.add_field(
            name=f"Reminder #{i}",
            value=f"**{reminder['message']}**\nIn ~{minutes_left} minute{'s' if minutes_left != 1 else ''}",
            inline=False
        )
    
    embed.set_footer(text="Made with magical love 💕✨")
    await interaction.response.send_message(embed=embed)

@tasks.loop(seconds=30)
async def check_reminders():
    current_time = datetime.now()
    
    for reminder in reminders[:]:
        reminder_time = datetime.fromisoformat(reminder['time'])
        
        if current_time >= reminder_time:
            channel = bot.get_channel(reminder['channel_id'])
            user = bot.get_user(reminder['user_id'])
            
            if channel and user:
                embed = discord.Embed(
                    title="⏰ Magical Reminder! 💕",
                    description=reminder['message'],
                    color=discord.Color.pink()
                )
                embed.set_footer(text="With love from your magical bot 💖✨")
                
                await channel.send(f"{user.mention}", embed=embed)
            
            reminders.remove(reminder)

# Run the bot
if __name__ == "__main__":
    print("💖 Starting the Magical Love Bot...")
    print("⚠️  Remember to add your Discord bot token!")
    print("📝 Slash commands will sync when the bot starts!")
    
    token = os.getenv('DISCORD_TOKEN')
    if not token:
        print("\n❌ ERROR: No Discord token found!")
        print("Please set the DISCORD_TOKEN environment variable")
        print("Create a .env file with: DISCORD_TOKEN=your_token_here")
        exit(1)
    
    bot.run(token)

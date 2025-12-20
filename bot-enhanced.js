const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, PermissionFlagsBits } = require('discord.js');
const { joinVoiceChannel, createAudioPlayer, createAudioResource, AudioPlayerStatus, VoiceConnectionStatus, entersState } = require('@discordjs/voice');
const ytdl = require('@distube/ytdl-core');
const ytSearch = require('yt-search');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.GuildVoiceStates,
        GatewayIntentBits.MessageContent
    ]
});

const queue = new Map();
const playerChannels = new Map(); // Store player channel IDs per guild

client.on('ready', async () => {
    console.log(`Logged in as ${client.user.tag}!`);
    
    // Register slash commands
    const commands = [
        {
            name: 'play',
            description: 'Play a song from YouTube',
            options: [
                {
                    name: 'song',
                    type: 3, // STRING type
                    description: 'Song name or YouTube URL',
                    required: true
                }
            ]
        },
        {
            name: 'skip',
            description: 'Skip the current song'
        },
        {
            name: 'stop',
            description: 'Stop playback and clear the queue'
        },
        {
            name: 'pause',
            description: 'Pause the current song'
        },
        {
            name: 'resume',
            description: 'Resume the paused song'
        },
        {
            name: 'queue',
            description: 'Show the current queue'
        },
        {
            name: 'nowplaying',
            description: 'Show the currently playing song'
        },
        {
            name: 'setup-player',
            description: 'Create a music player channel with control buttons',
            options: [
                {
                    name: 'channel-name',
                    type: 3, // STRING type
                    description: 'Name for the music player channel',
                    required: false
                }
            ]
        }
    ];

    try {
        console.log('Registering slash commands...');
        await client.application.commands.set(commands);
        console.log('Slash commands registered successfully!');
    } catch (error) {
        console.error('Error registering commands:', error);
    }
});

// Handle slash commands
client.on('interactionCreate', async (interaction) => {
    if (interaction.isChatInputCommand()) {
        const { commandName } = interaction;

        if (commandName === 'play') {
            await handlePlay(interaction);
        } else if (commandName === 'skip') {
            await handleSkip(interaction);
        } else if (commandName === 'stop') {
            await handleStop(interaction);
        } else if (commandName === 'pause') {
            await handlePause(interaction);
        } else if (commandName === 'resume') {
            await handleResume(interaction);
        } else if (commandName === 'queue') {
            await handleQueue(interaction);
        } else if (commandName === 'nowplaying') {
            await handleNowPlaying(interaction);
        } else if (commandName === 'setup-player') {
            await handleSetupPlayer(interaction);
        }
    } else if (interaction.isButton()) {
        await handleButton(interaction);
    }
});

// Legacy prefix commands support
client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    if (!message.content.startsWith('!')) return;

    const args = message.content.slice(1).trim().split(/ +/);
    const command = args.shift().toLowerCase();

    if (command === 'play') {
        await playLegacy(message, args);
    } else if (command === 'skip') {
        skipLegacy(message);
    } else if (command === 'stop') {
        stopLegacy(message);
    } else if (command === 'pause') {
        pauseLegacy(message);
    } else if (command === 'resume') {
        resumeLegacy(message);
    } else if (command === 'queue') {
        showQueueLegacy(message);
    } else if (command === 'help') {
        message.channel.send(
            '**Music Bot Commands:**\n' +
            '**Slash Commands (Recommended):**\n' +
            '`/play <song>` - Play a song\n' +
            '`/pause` - Pause current song\n' +
            '`/resume` - Resume playback\n' +
            '`/skip` - Skip current song\n' +
            '`/stop` - Stop and clear queue\n' +
            '`/queue` - Show queue\n' +
            '`/nowplaying` - Show current song\n' +
            '`/setup-player` - Create interactive player channel\n\n' +
            '**Prefix Commands:**\n' +
            '`!play <song>` - Play a song\n' +
            '`!skip` - Skip current song\n' +
            '`!stop` - Stop and clear queue\n' +
            '`!pause` - Pause playback\n' +
            '`!resume` - Resume playback\n' +
            '`!queue` - Show queue'
        );
    }
});

async function handleSetupPlayer(interaction) {
    await interaction.deferReply();

    const channelName = interaction.options.getString('channel-name') || '🎵-music-player';

    try {
        // Check if user has admin permissions
        if (!interaction.member.permissions.has(PermissionFlagsBits.Administrator)) {
            return interaction.editReply('❌ You need Administrator permissions to set up a music player channel!');
        }

        // Create the channel
        const channel = await interaction.guild.channels.create({
            name: channelName,
            type: 0, // GUILD_TEXT
            topic: '🎵 Music Player - Use the buttons below to control playback',
            permissionOverwrites: [
                {
                    id: interaction.guild.id,
                    allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.ReadMessageHistory],
                    deny: [PermissionFlagsBits.SendMessages]
                },
                {
                    id: client.user.id,
                    allow: [PermissionFlagsBits.SendMessages, PermissionFlagsBits.EmbedLinks]
                }
            ]
        });

        // Store the channel ID
        playerChannels.set(interaction.guild.id, channel.id);

        // Create the player embed and buttons
        const embed = new EmbedBuilder()
            .setColor('#0099ff')
            .setTitle('🎵 Music Player')
            .setDescription('No song currently playing\n\nUse `/play <song>` to start playing music!')
            .addFields(
                { name: '⏸️ Status', value: 'Stopped', inline: true },
                { name: '📃 Queue', value: '0 songs', inline: true },
                { name: '🔊 Volume', value: '100%', inline: true }
            )
            .setTimestamp();

        const row = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setCustomId('play_pause')
                    .setLabel('⏸️ Pause')
                    .setStyle(ButtonStyle.Primary)
                    .setDisabled(true),
                new ButtonBuilder()
                    .setCustomId('skip')
                    .setLabel('⏭️ Skip')
                    .setStyle(ButtonStyle.Primary)
                    .setDisabled(true),
                new ButtonBuilder()
                    .setCustomId('stop')
                    .setLabel('⏹️ Stop')
                    .setStyle(ButtonStyle.Danger)
                    .setDisabled(true),
                new ButtonBuilder()
                    .setCustomId('queue_btn')
                    .setLabel('📃 Queue')
                    .setStyle(ButtonStyle.Secondary)
            );

        await channel.send({ embeds: [embed], components: [row] });

        await interaction.editReply(`✅ Music player channel created: <#${channel.id}>`);
    } catch (error) {
        console.error('Error creating player channel:', error);
        await interaction.editReply('❌ There was an error creating the music player channel!');
    }
}

async function handleButton(interaction) {
    const serverQueue = queue.get(interaction.guild.id);

    if (interaction.customId === 'play_pause') {
        if (!serverQueue || !serverQueue.songs.length) {
            return interaction.reply({ content: '❌ Nothing is playing!', ephemeral: true });
        }

        if (serverQueue.playing) {
            serverQueue.player.pause();
            serverQueue.playing = false;
            await interaction.reply({ content: '⏸️ Paused the music!', ephemeral: true });
        } else {
            serverQueue.player.unpause();
            serverQueue.playing = true;
            await interaction.reply({ content: '▶️ Resumed the music!', ephemeral: true });
        }
        
        await updatePlayerEmbed(interaction.guild.id);
    } else if (interaction.customId === 'skip') {
        if (!serverQueue || !serverQueue.songs.length) {
            return interaction.reply({ content: '❌ Nothing is playing!', ephemeral: true });
        }

        serverQueue.player.stop();
        await interaction.reply({ content: '⏭️ Skipped the song!', ephemeral: true });
    } else if (interaction.customId === 'stop') {
        if (!serverQueue) {
            return interaction.reply({ content: '❌ Nothing is playing!', ephemeral: true });
        }

        serverQueue.songs = [];
        serverQueue.player.stop();
        serverQueue.connection.destroy();
        queue.delete(interaction.guild.id);
        await interaction.reply({ content: '⏹️ Stopped the music and cleared the queue!', ephemeral: true });
        await updatePlayerEmbed(interaction.guild.id);
    } else if (interaction.customId === 'queue_btn') {
        if (!serverQueue || !serverQueue.songs.length) {
            return interaction.reply({ content: '📃 The queue is empty!', ephemeral: true });
        }

        let queueMessage = '**Current Queue:**\n';
        serverQueue.songs.slice(0, 10).forEach((song, index) => {
            queueMessage += `${index + 1}. ${song.title}\n`;
        });

        if (serverQueue.songs.length > 10) {
            queueMessage += `\n... and ${serverQueue.songs.length - 10} more songs`;
        }

        await interaction.reply({ content: queueMessage, ephemeral: true });
    }
}

async function updatePlayerEmbed(guildId) {
    const channelId = playerChannels.get(guildId);
    if (!channelId) return;

    const channel = client.channels.cache.get(channelId);
    if (!channel) return;

    const serverQueue = queue.get(guildId);
    
    try {
        const messages = await channel.messages.fetch({ limit: 1 });
        const playerMessage = messages.first();
        if (!playerMessage) return;

        let embed;
        let row;

        if (!serverQueue || !serverQueue.songs.length) {
            embed = new EmbedBuilder()
                .setColor('#0099ff')
                .setTitle('🎵 Music Player')
                .setDescription('No song currently playing\n\nUse `/play <song>` to start playing music!')
                .addFields(
                    { name: '⏸️ Status', value: 'Stopped', inline: true },
                    { name: '📃 Queue', value: '0 songs', inline: true },
                    { name: '🔊 Volume', value: '100%', inline: true }
                )
                .setTimestamp();

            row = new ActionRowBuilder()
                .addComponents(
                    new ButtonBuilder()
                        .setCustomId('play_pause')
                        .setLabel('⏸️ Pause')
                        .setStyle(ButtonStyle.Primary)
                        .setDisabled(true),
                    new ButtonBuilder()
                        .setCustomId('skip')
                        .setLabel('⏭️ Skip')
                        .setStyle(ButtonStyle.Primary)
                        .setDisabled(true),
                    new ButtonBuilder()
                        .setCustomId('stop')
                        .setLabel('⏹️ Stop')
                        .setStyle(ButtonStyle.Danger)
                        .setDisabled(true),
                    new ButtonBuilder()
                        .setCustomId('queue_btn')
                        .setLabel('📃 Queue')
                        .setStyle(ButtonStyle.Secondary)
                );
        } else {
            const currentSong = serverQueue.songs[0];
            const status = serverQueue.playing ? 'Playing' : 'Paused';
            const statusEmoji = serverQueue.playing ? '▶️' : '⏸️';

            embed = new EmbedBuilder()
                .setColor(serverQueue.playing ? '#00ff00' : '#ffaa00')
                .setTitle('🎵 Music Player')
                .setDescription(`**Now Playing:**\n${currentSong.title}`)
                .addFields(
                    { name: '⏸️ Status', value: status, inline: true },
                    { name: '📃 Queue', value: `${serverQueue.songs.length} song(s)`, inline: true },
                    { name: '🔊 Volume', value: '100%', inline: true }
                )
                .setTimestamp();

            row = new ActionRowBuilder()
                .addComponents(
                    new ButtonBuilder()
                        .setCustomId('play_pause')
                        .setLabel(serverQueue.playing ? '⏸️ Pause' : '▶️ Resume')
                        .setStyle(ButtonStyle.Primary),
                    new ButtonBuilder()
                        .setCustomId('skip')
                        .setLabel('⏭️ Skip')
                        .setStyle(ButtonStyle.Primary),
                    new ButtonBuilder()
                        .setCustomId('stop')
                        .setLabel('⏹️ Stop')
                        .setStyle(ButtonStyle.Danger),
                    new ButtonBuilder()
                        .setCustomId('queue_btn')
                        .setLabel('📃 Queue')
                        .setStyle(ButtonStyle.Secondary)
                );
        }

        await playerMessage.edit({ embeds: [embed], components: [row] });
    } catch (error) {
        console.error('Error updating player embed:', error);
    }
}

async function handlePlay(interaction) {
    await interaction.deferReply();

    const voiceChannel = interaction.member.voice.channel;
    
    if (!voiceChannel) {
        return interaction.editReply('❌ You need to be in a voice channel to play music!');
    }

    const songInput = interaction.options.getString('song');
    const serverQueue = queue.get(interaction.guild.id);
    let song;

    try {
        if (songInput.includes('youtube.com') || songInput.includes('youtu.be')) {
            const songInfo = await ytdl.getInfo(songInput);
            song = {
                title: songInfo.videoDetails.title,
                url: songInfo.videoDetails.video_url,
            };
        } else {
            const videoResult = await ytSearch(songInput);
            if (!videoResult.videos.length) {
                return interaction.editReply('❌ No results found!');
            }
            
            song = {
                title: videoResult.videos[0].title,
                url: videoResult.videos[0].url,
            };
        }
    } catch (error) {
        console.error(error);
        return interaction.editReply('❌ There was an error searching for that song!');
    }

    if (!serverQueue) {
        const queueConstruct = {
            textChannel: interaction.channel,
            voiceChannel: voiceChannel,
            connection: null,
            songs: [],
            player: createAudioPlayer(),
            playing: true,
        };

        queue.set(interaction.guild.id, queueConstruct);
        queueConstruct.songs.push(song);

        try {
            const connection = joinVoiceChannel({
                channelId: voiceChannel.id,
                guildId: interaction.guild.id,
                adapterCreator: interaction.guild.voiceAdapterCreator,
            });

            queueConstruct.connection = connection;
            
            connection.on(VoiceConnectionStatus.Disconnected, async () => {
                try {
                    await Promise.race([
                        entersState(connection, VoiceConnectionStatus.Signalling, 5_000),
                        entersState(connection, VoiceConnectionStatus.Connecting, 5_000),
                    ]);
                } catch (error) {
                    connection.destroy();
                    queue.delete(interaction.guild.id);
                    await updatePlayerEmbed(interaction.guild.id);
                }
            });

            await playSong(interaction.guild, queueConstruct.songs[0]);
            await interaction.editReply(`🎵 Now playing: **${song.title}**`);
        } catch (err) {
            console.error(err);
            queue.delete(interaction.guild.id);
            return interaction.editReply('❌ There was an error joining the voice channel!');
        }
    } else {
        serverQueue.songs.push(song);
        await interaction.editReply(`✅ **${song.title}** has been added to the queue!`);
        await updatePlayerEmbed(interaction.guild.id);
    }
}

async function playSong(guild, song) {
    const serverQueue = queue.get(guild.id);

    if (!song) {
        serverQueue.connection.destroy();
        queue.delete(guild.id);
        await updatePlayerEmbed(guild.id);
        return;
    }

    const stream = ytdl(song.url, {
        filter: 'audioonly',
        quality: 'highestaudio',
        highWaterMark: 1 << 25
    });

    const resource = createAudioResource(stream);
    
    serverQueue.player.play(resource);
    serverQueue.connection.subscribe(serverQueue.player);
    serverQueue.playing = true;

    serverQueue.player.removeAllListeners(AudioPlayerStatus.Idle);
    serverQueue.player.on(AudioPlayerStatus.Idle, async () => {
        serverQueue.songs.shift();
        await playSong(guild, serverQueue.songs[0]);
    });

    serverQueue.player.removeAllListeners('error');
    serverQueue.player.on('error', async error => {
        console.error('Audio player error:', error);
        serverQueue.songs.shift();
        await playSong(guild, serverQueue.songs[0]);
    });

    if (serverQueue.textChannel) {
        serverQueue.textChannel.send(`🎵 Now playing: **${song.title}**`);
    }

    await updatePlayerEmbed(guild.id);
}

async function handleSkip(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '❌ You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue) {
        return interaction.reply({ content: '❌ There is no song playing!', ephemeral: true });
    }
    
    serverQueue.player.stop();
    await interaction.reply('⏭️ Skipped the song!');
}

async function handleStop(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '❌ You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue) {
        return interaction.reply({ content: '❌ There is no song playing!', ephemeral: true });
    }
    
    serverQueue.songs = [];
    serverQueue.player.stop();
    serverQueue.connection.destroy();
    queue.delete(interaction.guild.id);
    await interaction.reply('⏹️ Stopped the music and cleared the queue!');
    await updatePlayerEmbed(interaction.guild.id);
}

async function handlePause(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '❌ You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue || !serverQueue.playing) {
        return interaction.reply({ content: '❌ There is nothing playing!', ephemeral: true });
    }
    
    serverQueue.player.pause();
    serverQueue.playing = false;
    await interaction.reply('⏸️ Paused the music!');
    await updatePlayerEmbed(interaction.guild.id);
}

async function handleResume(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '❌ You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue || serverQueue.playing) {
        return interaction.reply({ content: '❌ The music is already playing!', ephemeral: true });
    }
    
    serverQueue.player.unpause();
    serverQueue.playing = true;
    await interaction.reply('▶️ Resumed the music!');
    await updatePlayerEmbed(interaction.guild.id);
}

async function handleQueue(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!serverQueue || !serverQueue.songs.length) {
        return interaction.reply({ content: '📃 The queue is empty!', ephemeral: true });
    }
    
    const embed = new EmbedBuilder()
        .setColor('#0099ff')
        .setTitle('📃 Current Queue')
        .setDescription(
            serverQueue.songs.slice(0, 10).map((song, index) => 
                `${index + 1}. ${song.title}`
            ).join('\n')
        )
        .setFooter({ text: `${serverQueue.songs.length} song(s) in queue` })
        .setTimestamp();

    if (serverQueue.songs.length > 10) {
        embed.addFields({ name: 'And more...', value: `${serverQueue.songs.length - 10} more songs` });
    }

    await interaction.reply({ embeds: [embed] });
}

async function handleNowPlaying(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!serverQueue || !serverQueue.songs.length) {
        return interaction.reply({ content: '❌ Nothing is currently playing!', ephemeral: true });
    }

    const currentSong = serverQueue.songs[0];
    const embed = new EmbedBuilder()
        .setColor('#00ff00')
        .setTitle('🎵 Now Playing')
        .setDescription(currentSong.title)
        .addFields(
            { name: 'Status', value: serverQueue.playing ? '▶️ Playing' : '⏸️ Paused', inline: true },
            { name: 'Songs in Queue', value: `${serverQueue.songs.length}`, inline: true }
        )
        .setTimestamp();

    await interaction.reply({ embeds: [embed] });
}

// Legacy command handlers
async function playLegacy(message, args) {
    const voiceChannel = message.member.voice.channel;
    
    if (!voiceChannel) {
        return message.channel.send('❌ You need to be in a voice channel to play music!');
    }

    if (!args.length) {
        return message.channel.send('❌ Please provide a song name or URL!');
    }

    const serverQueue = queue.get(message.guild.id);
    let song;

    try {
        const searchString = args.join(' ');
        
        if (searchString.includes('youtube.com') || searchString.includes('youtu.be')) {
            const songInfo = await ytdl.getInfo(searchString);
            song = {
                title: songInfo.videoDetails.title,
                url: songInfo.videoDetails.video_url,
            };
        } else {
            const videoResult = await ytSearch(searchString);
            if (!videoResult.videos.length) {
                return message.channel.send('❌ No results found!');
            }
            
            song = {
                title: videoResult.videos[0].title,
                url: videoResult.videos[0].url,
            };
        }
    } catch (error) {
        console.error(error);
        return message.channel.send('❌ There was an error searching for that song!');
    }

    if (!serverQueue) {
        const queueConstruct = {
            textChannel: message.channel,
            voiceChannel: voiceChannel,
            connection: null,
            songs: [],
            player: createAudioPlayer(),
            playing: true,
        };

        queue.set(message.guild.id, queueConstruct);
        queueConstruct.songs.push(song);

        try {
            const connection = joinVoiceChannel({
                channelId: voiceChannel.id,
                guildId: message.guild.id,
                adapterCreator: message.guild.voiceAdapterCreator,
            });

            queueConstruct.connection = connection;
            
            connection.on(VoiceConnectionStatus.Disconnected, async () => {
                try {
                    await Promise.race([
                        entersState(connection, VoiceConnectionStatus.Signalling, 5_000),
                        entersState(connection, VoiceConnectionStatus.Connecting, 5_000),
                    ]);
                } catch (error) {
                    connection.destroy();
                    queue.delete(message.guild.id);
                    await updatePlayerEmbed(message.guild.id);
                }
            });

            await playSong(message.guild, queueConstruct.songs[0]);
        } catch (err) {
            console.error(err);
            queue.delete(message.guild.id);
            return message.channel.send('❌ There was an error joining the voice channel!');
        }
    } else {
        serverQueue.songs.push(song);
        message.channel.send(`✅ **${song.title}** has been added to the queue!`);
        await updatePlayerEmbed(message.guild.id);
    }
}

function skipLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('❌ You need to be in a voice channel!');
    }
    
    if (!serverQueue) {
        return message.channel.send('❌ There is no song playing!');
    }
    
    serverQueue.player.stop();
    message.channel.send('⏭️ Skipped the song!');
}

function stopLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('❌ You need to be in a voice channel!');
    }
    
    if (!serverQueue) {
        return message.channel.send('❌ There is no song playing!');
    }
    
    serverQueue.songs = [];
    serverQueue.player.stop();
    serverQueue.connection.destroy();
    queue.delete(message.guild.id);
    message.channel.send('⏹️ Stopped the music and cleared the queue!');
    updatePlayerEmbed(message.guild.id);
}

function pauseLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('❌ You need to be in a voice channel!');
    }
    
    if (!serverQueue || !serverQueue.playing) {
        return message.channel.send('❌ There is nothing playing!');
    }
    
    serverQueue.player.pause();
    serverQueue.playing = false;
    message.channel.send('⏸️ Paused the music!');
    updatePlayerEmbed(message.guild.id);
}

function resumeLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('❌ You need to be in a voice channel!');
    }
    
    if (!serverQueue || serverQueue.playing) {
        return message.channel.send('❌ The music is already playing!');
    }
    
    serverQueue.player.unpause();
    serverQueue.playing = true;
    message.channel.send('▶️ Resumed the music!');
    updatePlayerEmbed(message.guild.id);
}

function showQueueLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!serverQueue || !serverQueue.songs.length) {
        return message.channel.send('📃 The queue is empty!');
    }
    
    let queueMessage = '**Current Queue:**\n';
    serverQueue.songs.forEach((song, index) => {
        queueMessage += `${index + 1}. ${song.title}\n`;
    });
    
    message.channel.send(queueMessage);
}

client.login(process.env.DISCORD_TOKEN);

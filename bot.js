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
    console.log(`✨ Supernova is online! Spreading love and music! ✨`);
    console.log(`Logged in as ${client.user.tag}!`);
    
    // Register slash commands
    const commands = [
        {
            name: 'play',
            description: '💖 Summon a song with the power of love! 🎵',
            options: [
                {
                    name: 'song',
                    type: 3, // STRING type
                    description: 'The melody your heart desires ✨',
                    required: true
                }
            ]
        },
        {
            name: 'skip',
            description: '💫 Skip to the next lovely melody!'
        },
        {
            name: 'stop',
            description: '💔 End the concert and clear your heart'
        },
        {
            name: 'pause',
            description: '⏸️ Pause this moment of love'
        },
        {
            name: 'resume',
            description: '💗 Let the love flow again!'
        },
        {
            name: 'queue',
            description: '📜 Peek at your playlist of love songs'
        },
        {
            name: 'nowplaying',
            description: '💖 See what melody fills your heart right now'
        },
        {
            name: 'setup-player',
            description: '✨ Create a magical music sanctuary! (Admin only)',
            options: [
                {
                    name: 'channel-name',
                    type: 3, // STRING type
                    description: 'Name your love-filled sanctuary ✨',
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
            '✨💖 **Supernova\'s Magical Commands!** 💖✨\n\n' +
            '**✨ Slash Commands (The Power of Love!):**\n' +
            '`/play <song>` - Summon a lovely melody! 🎵\n' +
            '`/pause` - Pause this moment of love ⏸️\n' +
            '`/resume` - Let the love flow again! 💗\n' +
            '`/skip` - Skip to the next melody! 💫\n' +
            '`/stop` - End the concert 💔\n' +
            '`/queue` - View your playlist of love 📜\n' +
            '`/nowplaying` - Current heart song 💖\n' +
            '`/setup-player` - Create magical sanctuary! ✨\n\n' +
            '**💝 Classic Commands:**\n' +
            '`!play <song>` - Summon a song\n' +
            '`!skip` - Next song please!\n' +
            '`!stop` - Stop the music\n' +
            '`!pause` - Pause playback\n' +
            '`!resume` - Resume playback\n' +
            '`!queue` - Show queue\n\n' +
            '*Powered by the magic of love! 💫*'
        );
    }
});

async function handleSetupPlayer(interaction) {
    await interaction.deferReply();

    const channelName = interaction.options.getString('channel-name') || '💖-supernova-sanctuary';

    try {
        // Check if user has admin permissions
        if (!interaction.member.permissions.has(PermissionFlagsBits.Administrator)) {
            return interaction.editReply('✨ Only magical guardians (Administrators) can create sanctuaries! 💫');
        }

        // Create the channel
        const channel = await interaction.guild.channels.create({
            name: channelName,
            type: 0, // GUILD_TEXT
            topic: '✨💖 Supernova\'s Love-Filled Sanctuary - Control the magic with buttons below! 💫',
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
            .setColor('#FF69B4')
            .setTitle('✨💖 Supernova\'s Love Sanctuary 💖✨')
            .setDescription('*Awaiting your heart\'s melody...*\n\nUse `/play <song>` to fill this space with love and music! 🎵')
            .addFields(
                { name: '💫 Status', value: 'Dreaming ✨', inline: true },
                { name: '📜 Queue', value: '0 love songs', inline: true },
                { name: '💕 Power', value: '100% Love Energy', inline: true }
            )
            .setFooter({ text: '💫 Magical Girl Supernova 💫' })
            .setTimestamp();

        const row = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setCustomId('play_pause')
                    .setLabel('💗 Pause')
                    .setStyle(ButtonStyle.Primary)
                    .setDisabled(true),
                new ButtonBuilder()
                    .setCustomId('skip')
                    .setLabel('💫 Skip')
                    .setStyle(ButtonStyle.Primary)
                    .setDisabled(true),
                new ButtonBuilder()
                    .setCustomId('stop')
                    .setLabel('💔 Stop')
                    .setStyle(ButtonStyle.Danger)
                    .setDisabled(true),
                new ButtonBuilder()
                    .setCustomId('queue_btn')
                    .setLabel('📜 Playlist')
                    .setStyle(ButtonStyle.Secondary)
            );

        await channel.send({ embeds: [embed], components: [row] });

        await interaction.editReply(`💖✨ Magical sanctuary created! Welcome to <#${channel.id}> ✨💖`);
    } catch (error) {
        console.error('Error creating player channel:', error);
        await interaction.editReply('❌ There was an error creating the music player channel!');
    }
}

async function handleButton(interaction) {
    const serverQueue = queue.get(interaction.guild.id);

    if (interaction.customId === 'play_pause') {
        if (!serverQueue || !serverQueue.songs.length) {
            return interaction.reply({ content: '💫 No melody is playing right now!', ephemeral: true });
        }

        if (serverQueue.playing) {
            serverQueue.player.pause();
            serverQueue.playing = false;
            await interaction.reply({ content: '💗 Pausing this lovely moment...', ephemeral: true });
        } else {
            serverQueue.player.unpause();
            serverQueue.playing = true;
            await interaction.reply({ content: '💖 The love flows again!', ephemeral: true });
        }
        
        await updatePlayerEmbed(interaction.guild.id);
    } else if (interaction.customId === 'skip') {
        if (!serverQueue || !serverQueue.songs.length) {
            return interaction.reply({ content: '💫 No melody is playing right now!', ephemeral: true });
        }

        serverQueue.player.stop();
        await interaction.reply({ content: '💫 Skipping to the next melody!', ephemeral: true });
    } else if (interaction.customId === 'stop') {
        if (!serverQueue) {
            return interaction.reply({ content: '💫 No melody is playing right now!', ephemeral: true });
        }

        serverQueue.songs = [];
        serverQueue.player.stop();
        serverQueue.connection.destroy();
        queue.delete(interaction.guild.id);
        await interaction.reply({ content: '💔 The concert has ended... Until next time!', ephemeral: true });
        await updatePlayerEmbed(interaction.guild.id);
    } else if (interaction.customId === 'queue_btn') {
        if (!serverQueue || !serverQueue.songs.length) {
            return interaction.reply({ content: '📜 Your playlist is empty! Add some love songs! 💕', ephemeral: true });
        }

        let queueMessage = '**💖 Your Playlist of Love:**\n\n';
        serverQueue.songs.slice(0, 10).forEach((song, index) => {
            const emoji = index === 0 ? '💗' : '💕';
            queueMessage += `${emoji} ${index + 1}. ${song.title}\n`;
        });

        if (serverQueue.songs.length > 10) {
            queueMessage += `\n✨ ... and ${serverQueue.songs.length - 10} more lovely melodies!`;
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
                .setColor('#FF69B4')
                .setTitle('✨💖 Supernova\'s Love Sanctuary 💖✨')
                .setDescription('*Awaiting your heart\'s melody...*\n\nUse `/play <song>` to fill this space with love and music! 🎵')
                .addFields(
                    { name: '💫 Status', value: 'Dreaming ✨', inline: true },
                    { name: '📜 Queue', value: '0 love songs', inline: true },
                    { name: '💕 Power', value: '100% Love Energy', inline: true }
                )
                .setFooter({ text: '💫 Magical Girl Supernova 💫' })
                .setTimestamp();

            row = new ActionRowBuilder()
                .addComponents(
                    new ButtonBuilder()
                        .setCustomId('play_pause')
                        .setLabel('💗 Pause')
                        .setStyle(ButtonStyle.Primary)
                        .setDisabled(true),
                    new ButtonBuilder()
                        .setCustomId('skip')
                        .setLabel('💫 Skip')
                        .setStyle(ButtonStyle.Primary)
                        .setDisabled(true),
                    new ButtonBuilder()
                        .setCustomId('stop')
                        .setLabel('💔 Stop')
                        .setStyle(ButtonStyle.Danger)
                        .setDisabled(true),
                    new ButtonBuilder()
                        .setCustomId('queue_btn')
                        .setLabel('📜 Playlist')
                        .setStyle(ButtonStyle.Secondary)
                );
        } else {
            const currentSong = serverQueue.songs[0];
            const status = serverQueue.playing ? '💖 Spreading Love' : '💗 Paused';
            const statusEmoji = serverQueue.playing ? '✨' : '💫';

            embed = new EmbedBuilder()
                .setColor(serverQueue.playing ? '#FF1493' : '#FFB6C1')
                .setTitle('✨💖 Supernova\'s Love Sanctuary 💖✨')
                .setDescription(`**${statusEmoji} Now Playing:**\n*${currentSong.title}*\n\n💕 Let the melody fill your heart!`)
                .addFields(
                    { name: '💫 Status', value: status, inline: true },
                    { name: '📜 Queue', value: `${serverQueue.songs.length} love song(s)`, inline: true },
                    { name: '💕 Power', value: '100% Love Energy', inline: true }
                )
                .setFooter({ text: '💫 Magical Girl Supernova 💫' })
                .setTimestamp();

            row = new ActionRowBuilder()
                .addComponents(
                    new ButtonBuilder()
                        .setCustomId('play_pause')
                        .setLabel(serverQueue.playing ? '💗 Pause' : '💖 Resume')
                        .setStyle(ButtonStyle.Primary),
                    new ButtonBuilder()
                        .setCustomId('skip')
                        .setLabel('💫 Skip')
                        .setStyle(ButtonStyle.Primary),
                    new ButtonBuilder()
                        .setCustomId('stop')
                        .setLabel('💔 Stop')
                        .setStyle(ButtonStyle.Danger),
                    new ButtonBuilder()
                        .setCustomId('queue_btn')
                        .setLabel('📜 Playlist')
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
        return interaction.editReply('💫 You need to be in a voice channel to summon melodies!');
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
                return interaction.editReply('💔 No melodies found! Try another search!');
            }
            
            song = {
                title: videoResult.videos[0].title,
                url: videoResult.videos[0].url,
            };
        }
    } catch (error) {
        console.error(error);
        return interaction.editReply('💫 There was an error searching for that melody!');
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
            await interaction.editReply(`💖 Now playing: **${song.title}** ✨`);
        } catch (err) {
            console.error(err);
            queue.delete(interaction.guild.id);
            return interaction.editReply('💫 There was an error joining the voice channel!');
        }
    } else {
        serverQueue.songs.push(song);
        await interaction.editReply(`💕 **${song.title}** has been added to your playlist of love!`);
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
        serverQueue.textChannel.send(`💖✨ Now playing: **${song.title}** ✨💖`);
    }

    await updatePlayerEmbed(guild.id);
}

async function handleSkip(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '💫 You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue) {
        return interaction.reply({ content: '💫 There is no melody playing right now!', ephemeral: true });
    }
    
    serverQueue.player.stop();
    await interaction.reply('💫 Skipping to the next lovely melody!');
}

async function handleStop(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '💫 You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue) {
        return interaction.reply({ content: '💫 There is no melody playing right now!', ephemeral: true });
    }
    
    serverQueue.songs = [];
    serverQueue.player.stop();
    serverQueue.connection.destroy();
    queue.delete(interaction.guild.id);
    await interaction.reply('💔 The concert has ended... Until we meet again! 💫');
    await updatePlayerEmbed(interaction.guild.id);
}

async function handlePause(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '💫 You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue || !serverQueue.playing) {
        return interaction.reply({ content: '💫 There is nothing playing right now!', ephemeral: true });
    }
    
    serverQueue.player.pause();
    serverQueue.playing = false;
    await interaction.reply('💗 Pausing this lovely moment...');
    await updatePlayerEmbed(interaction.guild.id);
}

async function handleResume(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!interaction.member.voice.channel) {
        return interaction.reply({ content: '💫 You need to be in a voice channel!', ephemeral: true });
    }
    
    if (!serverQueue || serverQueue.playing) {
        return interaction.reply({ content: '💖 The love is already flowing!', ephemeral: true });
    }
    
    serverQueue.player.unpause();
    serverQueue.playing = true;
    await interaction.reply('💖 The love flows again!');
    await updatePlayerEmbed(interaction.guild.id);
}

async function handleQueue(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!serverQueue || !serverQueue.songs.length) {
        return interaction.reply({ content: '📜 Your playlist is empty! Add some love songs with `/play`! 💕', ephemeral: true });
    }
    
    const embed = new EmbedBuilder()
        .setColor('#FF69B4')
        .setTitle('📜✨ Your Playlist of Love ✨📜')
        .setDescription(
            serverQueue.songs.slice(0, 10).map((song, index) => {
                const emoji = index === 0 ? '💗' : '💕';
                return `${emoji} **${index + 1}.** ${song.title}`;
            }).join('\n')
        )
        .setFooter({ text: `${serverQueue.songs.length} love song(s) • Powered by Supernova 💫` })
        .setTimestamp();

    if (serverQueue.songs.length > 10) {
        embed.addFields({ name: '✨ And more...', value: `💖 ${serverQueue.songs.length - 10} more lovely melodies!` });
    }

    await interaction.reply({ embeds: [embed] });
}

async function handleNowPlaying(interaction) {
    const serverQueue = queue.get(interaction.guild.id);
    
    if (!serverQueue || !serverQueue.songs.length) {
        return interaction.reply({ content: '💫 No melody is playing right now! Use `/play` to summon one! ✨', ephemeral: true });
    }

    const currentSong = serverQueue.songs[0];
    const embed = new EmbedBuilder()
        .setColor('#FF1493')
        .setTitle('💖✨ Now Playing ✨💖')
        .setDescription(`*${currentSong.title}*\n\n💕 Let this melody fill your heart!`)
        .addFields(
            { name: '💫 Status', value: serverQueue.playing ? '💖 Spreading Love' : '💗 Paused', inline: true },
            { name: '📜 In Queue', value: `${serverQueue.songs.length} love song(s)`, inline: true }
        )
        .setFooter({ text: '💫 Magical Girl Supernova 💫' })
        .setTimestamp();

    await interaction.reply({ embeds: [embed] });
}

// Legacy command handlers
async function playLegacy(message, args) {
    const voiceChannel = message.member.voice.channel;
    
    if (!voiceChannel) {
        return message.channel.send('💫 You need to be in a voice channel to summon melodies!');
    }

    if (!args.length) {
        return message.channel.send('💫 Please tell me what melody to summon!');
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
                return message.channel.send('💔 No melodies found! Try another search!');
            }
            
            song = {
                title: videoResult.videos[0].title,
                url: videoResult.videos[0].url,
            };
        }
    } catch (error) {
        console.error(error);
        return message.channel.send('💫 There was an error searching for that melody!');
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
            return message.channel.send('💫 There was an error joining the voice channel!');
        }
    } else {
        serverQueue.songs.push(song);
        message.channel.send(`💕 **${song.title}** has been added to your playlist of love!`);
        await updatePlayerEmbed(message.guild.id);
    }
}

function skipLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('💫 You need to be in a voice channel!');
    }
    
    if (!serverQueue) {
        return message.channel.send('💫 There is no melody playing right now!');
    }
    
    serverQueue.player.stop();
    message.channel.send('💫 Skipping to the next lovely melody!');
}

function stopLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('💫 You need to be in a voice channel!');
    }
    
    if (!serverQueue) {
        return message.channel.send('💫 There is no melody playing right now!');
    }
    
    serverQueue.songs = [];
    serverQueue.player.stop();
    serverQueue.connection.destroy();
    queue.delete(message.guild.id);
    message.channel.send('💔 The concert has ended... Until we meet again! 💫');
    updatePlayerEmbed(message.guild.id);
}

function pauseLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('💫 You need to be in a voice channel!');
    }
    
    if (!serverQueue || !serverQueue.playing) {
        return message.channel.send('💫 There is nothing playing right now!');
    }
    
    serverQueue.player.pause();
    serverQueue.playing = false;
    message.channel.send('💗 Pausing this lovely moment...');
    updatePlayerEmbed(message.guild.id);
}

function resumeLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!message.member.voice.channel) {
        return message.channel.send('💫 You need to be in a voice channel!');
    }
    
    if (!serverQueue || serverQueue.playing) {
        return message.channel.send('💖 The love is already flowing!');
    }
    
    serverQueue.player.unpause();
    serverQueue.playing = true;
    message.channel.send('💖 The love flows again!');
    updatePlayerEmbed(message.guild.id);
}

function showQueueLegacy(message) {
    const serverQueue = queue.get(message.guild.id);
    
    if (!serverQueue || !serverQueue.songs.length) {
        return message.channel.send('📜 Your playlist is empty! Add some love songs! 💕');
    }
    
    let queueMessage = '**💖 Your Playlist of Love:**\n\n';
    serverQueue.songs.forEach((song, index) => {
        const emoji = index === 0 ? '💗' : '💕';
        queueMessage += `${emoji} ${index + 1}. ${song.title}\n`;
    });
    
    message.channel.send(queueMessage);
}

client.login(process.env.DISCORD_TOKEN);

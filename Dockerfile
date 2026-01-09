# Use Node.js 20 - FORCING IT!
FROM node:20-alpine

# Install ffmpeg and other dependencies
RUN apk add --no-cache \
    ffmpeg \
    python3 \
    make \
    g++ \
    libsodium-dev

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Expose port (not really needed for Discord bot but good practice)
EXPOSE 3000

# Start the bot
CMD ["npm", "start"]

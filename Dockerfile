FROM node:20-alpine

# Install dependencies for media processing and link extraction (including curl)
RUN apk update && apk add --no-cache \
    ffmpeg \
    python3 \
    py3-pip \
    curl \
    && curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -o /usr/local/bin/yt-dlp \
    && chmod a+rx /usr/local/bin/yt-dlp

WORKDIR /app

# Install Node dependencies
COPY package*.json ./
RUN npm install

COPY . .

# Environment setup
ENV MEDIA_PATH=/app/media
ENV PORT=49690

EXPOSE 49690

CMD ["node", "server.js"]
FROM node:18-alpine

# openssl is needed to generate a self-signed dev certificate on first start
RUN apk add --no-cache openssl

WORKDIR /app

# Copy plugin source (server.js + all static HTML/JS/assets)
COPY . .

# Startup script: generates self-signed cert if no cert is mounted/present
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Plugin server listens on port 3000 (HTTPS)
EXPOSE 3000

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["node", "server.js"]

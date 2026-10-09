FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install

# Copy all source and build
COPY . .
RUN npm run build

# Output: /app/dist will be mounted to ../ui by docker-compose

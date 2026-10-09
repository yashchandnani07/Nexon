FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Final stage
FROM alpine:3.18
WORKDIR /built_dist
COPY --from=builder /app/dist .
CMD cp -a /built_dist/. /app/dist/

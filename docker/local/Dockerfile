# syntax=docker/dockerfile:1.7
FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev

COPY . .

RUN mkdir -p uploads .local

EXPOSE 3000

CMD ["node", "app.js"]

FROM node:20-alpine

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY . .

RUN npm install --omit=dev

EXPOSE 3000

CMD ["node", "server.js"]

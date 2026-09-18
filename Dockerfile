FROM node:20-alpine

# Herramientas necesarias para compilar better-sqlite3 (módulo nativo)
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copiamos solo los archivos de dependencias primero (mejor caché)
COPY package*.json ./

# Instalamos dependencias (sin devDependencies)
RUN npm ci --omit=dev

# Copiamos el resto del proyecto
COPY . .

# Railway inyecta su propia variable PORT, pero por defecto usamos 3000
ENV PORT=3000
EXPOSE 3000

# Arrancamos el servidor
CMD ["node", "server.js"]

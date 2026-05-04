FROM mcr.microsoft.com/playwright:v1.49.1-jammy

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY index.ts tsconfig.json ./
RUN ./node_modules/.bin/tsc

ENV PORT=8080
EXPOSE 8080
CMD ["node", "dist/index.js"]

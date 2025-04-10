FROM oven/bun:1.2.9-alpine

LABEL AUTHOR mkuhlmann

WORKDIR /app
COPY . .

EXPOSE 8080
CMD ["bun", "start"]
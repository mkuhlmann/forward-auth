FROM node:17-alpine

MAINTAINER mkuhlmann

WORKDIR /app
COPY . .
RUN npm install --only=production

EXPOSE 8080
CMD ["npm", "run", "docker"]
FROM node:11-alpine

MAINTAINER mkuhlmann

WORKDIR /app
COPY . .
RUN npm install

EXPOSE 8080
CMD ["npm", "run", "docker"]
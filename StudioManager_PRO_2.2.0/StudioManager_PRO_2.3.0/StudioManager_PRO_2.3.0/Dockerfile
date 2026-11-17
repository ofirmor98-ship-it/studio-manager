FROM node:22-alpine
WORKDIR /app
COPY . .
ENV PORT=3000
ENV STUDIO_DATA_DIR=/data
EXPOSE 3000
VOLUME ["/data"]
CMD ["node", "server.js"]

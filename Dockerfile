FROM core-harbor.eu-west-3.codefi.network/proxy_cache/library/node:14-alpine3.14 as builder
WORKDIR /home/node/app
COPY package.json ./
RUN npm install 
COPY . .
RUN npm run build


FROM core-harbor.eu-west-3.codefi.network/proxy_cache/library/nginx:1.21.5-alpine as runner
WORKDIR /var/www/app
COPY --from=builder /home/node/app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
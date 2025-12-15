FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG REACT_APP_API_URL=/api
ENV REACT_APP_API_URL=$REACT_APP_API_URL
RUN npm run build

FROM nginx:1.25-alpine AS production
COPY --from=build /app/build /usr/share/nginx/html
RUN echo 'server{listen 3000;root /usr/share/nginx/html;index index.html;location /{try_files $uri $uri/ /index.html;}}' > /etc/nginx/conf.d/default.conf
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]

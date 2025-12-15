FROM nginx:1.25-alpine
LABEL maintainer="IPSSI Student"
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY htpasswd /etc/nginx/htpasswd
RUN mkdir -p /var/log/nginx && chown -R nginx:nginx /var/cache/nginx /var/log/nginx
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/health || exit 1
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]

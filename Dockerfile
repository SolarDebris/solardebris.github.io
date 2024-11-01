FROM node:latest

CMD mkdir -p /app/
RUN apt-get update && apt-get install -y certbot cron python3 python3-pip python3-certbot-nginx nodejs npm 
RUN pip3 install --break-system-packages flask flask-cors gunicorn jwt

RUN git clone https://github.com/SolarDebris/solardebris.github.io /app
RUN git clone https://github.com/SolarDebris/blog_generator /app/blog_generator

RUN cp /app/crontab /etc/cron.d/update_website
RUN chmod 0644 /etc/cron.d/update_website
RUN crontab /etc/cron.d/update_website

WORKDIR /app/backend/
#CMD gunicorn -w 4 -b 0.0.0.0:5000 blog:app

WORKDIR /app/frontend/
RUN npm install
RUN npm run build
#RUN npm run preview --host
WORKDIR /app
RUN chmod +x /app/update.sh
RUN /app/update.sh

EXPOSE 3000
ENTRYPOINT ["/app/run.sh"]

FROM node:latest

CMD mkdir -p /app/
RUN apt-get update && apt-get install -y python3 python3-pip nodejs npm
RUN pip3 install --break-system-packages flask flask-cors gunicorn

RUN git clone https://github.com/SolarDebris/solardebris.github.io /app
RUN git clone https://github.com/SolarDebris/blog_generator

COPY /app/crontab /etc/cron.d/update_website
RUN chmod 0644 /etc/cron.d/update_website
RUN crontab /etc/cron.d/update_website

WORKDIR /app/backend/
#CMD gunicorn -w 4 -b 0.0.0.0:5000 blog:app

WORKDIR /app/frontend/
RUN npm install
RUN npm run build
#RUN npm run preview --host

EXPOSE 3000
ENTRYPOINT ["/app/run.sh"]

FROM node:latest


CMD mkdir -p /app/
RUN apt-get update && apt-get install -y python3 python3-pip nodejs npm
RUN pip3 install --break-system-packages flask flask-cors gunicorn

CMD mkdir -p /app/backend /app/frontend /app/blog_entries
COPY backend /app/backend/
COPY frontend /app/frontend/
COPY blog_entries /app/blog_entries/

WORKDIR /app/backend/
CMD python3 server.py

WORKDIR /app/frontend/
RUN npm install
RUN npm run build
#RUN npm run preview --host

EXPOSE 4173

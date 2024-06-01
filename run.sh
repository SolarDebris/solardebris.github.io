#!/bin/bash

cd /srv/solardebris.github.io/backend/
gunicorn -w 4 -b 0.0.0.0:5000 blog:app

cd /srv/solardebris.github.io/frontend
npm run build 
npm run start


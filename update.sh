#!/bin/bash

cd /app
git pull

certbot --nginx -n -d www.solardebris.xyz renew

cd /app/frontend
npm run build

cd /app
rm -rf ./html_files/*
./blog_generator/mdToHtml ./blog_entries/ ./html_files/

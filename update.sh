#!/bin/bash

cd /app
git pull

rm -rf ./html_files/*
./blog_generator/mdToHtml ./blog_entries/ ./html_files/

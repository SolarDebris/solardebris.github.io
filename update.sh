#!/bin/bash

cd /srv/solardebris.github.io
git pull

rm -rf ./html_files/*
./blog_generator/mdToHtml ./blog_entries/ ./html_files/

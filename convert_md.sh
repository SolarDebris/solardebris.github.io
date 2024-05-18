#!/bin/bash
#

rm -rf ./html_files/*
./blog_generator/mdToHtml ./blog_entries/ ./html_files/

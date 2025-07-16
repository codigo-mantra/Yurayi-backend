#!/bin/bash

# Define your project path
PROJECT_DIR="/home/ubuntu/project/Yurayi-backend"
cd "$PROJECT_DIR" || { echo "Project directory not found!"; exit 1; }

# Pull the latest code from GitHub
echo "Pulling latest code from GitHub..."
git pull origin master

# Reload and restart Gunicorn
echo "Reloading and restarting Gunicorn..."
sudo systemctl daemon-reload
sudo systemctl restart web.service
sudo systemctl enable web.service

# Restart and enable Nginx
echo "Restarting and enabling Nginx..."
sudo systemctl restart nginx.service
sudo systemctl enable nginx.service
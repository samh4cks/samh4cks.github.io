#!/bin/bash

# Load GitHub token from .bashrc
source ~/.bashrc

# Script filename (to exclude from commits)
script_name=$(basename "$0")

# Ask whether to commit all files or specific files
read -p "Do you want to commit all files (.) or specific files? [Type '.' or space-separated filenames]: " -a file_choice

# If committing all files, exclude this script
if [[ "${file_choice[0]}" == "." ]]; then
    git add .
    git reset -- "$script_name"  # Unstage the script itself
else
    git add "${file_choice[@]}"  # Add multiple files
fi

# Get commit message from user
read -p "Enter commit message: " commit_msg

# Commit changes
git commit -m "$commit_msg"

# Ask for GitHub username
read -p "Enter your GitHub username: " gh_username

# Push using stored GitHub token
echo "Pushing to GitHub..."
GIT_ASKPASS=$(mktemp)

# Create a temporary script to pass the password
echo "echo \$gh_token" > "$GIT_ASKPASS"
chmod +x "$GIT_ASKPASS"

# Push with authentication
GIT_ASKPASS="$GIT_ASKPASS" git push https://github.com/$gh_username/samh4cks.github.io.git main

# Remove the temporary file
rm "$GIT_ASKPASS"

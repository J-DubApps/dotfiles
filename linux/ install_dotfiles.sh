#!/bin/bash

# Define variables
REPO_URL="https://github.com/J-DubApps/dotfiles.git"
DOTFILES_DIR="$HOME/dotfiles"
BACKUP_DIR="$HOME/dotfiles_backup"

# Function to display messages
log() {
    echo -e "\033[1;32m$@\033[0m"
}

error() {
    echo -e "\033[1;31m$@\033[0m"
    exit 1
}

# Clone the repository
clone_repo() {
    if [ -d "$DOTFILES_DIR" ]; then
        log "Dotfiles directory already exists at $DOTFILES_DIR. Pulling latest changes..."
        git -C "$DOTFILES_DIR" pull || error "Failed to update the repository."
    else
        log "Cloning dotfiles repository..."
        git clone "$REPO_URL" "$DOTFILES_DIR" || error "Failed to clone the repository."
    fi
}

# Backup existing dotfiles
backup_dotfiles() {
    log "Backing up existing dotfiles to $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"

    # Loop through files in the repo
    for file in "$DOTFILES_DIR"/.*; do
        [ -f "$file" ] || continue
        base_file=$(basename "$file")
        target="$HOME/$base_file"

        if [ -e "$target" ] && [ ! -L "$target" ]; then
            log "Backing up $target..."
            mv "$target" "$BACKUP_DIR/" || error "Failed to back up $target."
        fi
    done
}

# Symlink dotfiles
symlink_dotfiles() {
    log "Creating symlinks for dotfiles..."
    for file in "$DOTFILES_DIR"/.*; do
        [ -f "$file" ] || continue
        base_file=$(basename "$file")
        target="$HOME/$base_file"

        if [ -L "$target" ]; then
            log "Removing existing symlink for $target..."
            rm "$target" || error "Failed to remove existing symlink for $target."
        fi

        log "Creating symlink for $base_file..."
        ln -s "$file" "$target" || error "Failed to create symlink for $base_file."
    done
}

# Main script execution
main() {
    log "Starting dotfiles installation..."

    clone_repo
    backup_dotfiles
    symlink_dotfiles

    log "Dotfiles installation complete!"
}

# Run the script
main
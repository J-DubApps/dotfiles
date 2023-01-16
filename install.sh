#!/bin/bash


# Check if running in bash shell vs zsh shell
if [ "$SHELL" == "/bin/bash" ]; then
  echo "Running in bash shell"
# Check if running in zsh shell
elif [ "$SHELL" == "/bin/zsh" ]; then
  echo "Running in zsh shell"
# Otherwise, unknown shell
else
  # echo "Error: Unknown shell"
fi


# Detect if running on Mac or Linux
if [ "$(uname)" == "Darwin" ]; then
    # Running on Mac, so run the Mac-specific command
    xcode-select --install
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
    brew bundle install
    brew install --cask visual-studio-code
else
    # Running on Linux, so do these other things instead
    :
fi

# install nix
# curl -L https://nixos.org/nix/install | sh

# source nix
# . ~/.nix-profile/etc/profile.d/nix.sh

# install packages
# nix-env -iA \
#	nixpkgs.zsh \
#	nixpkgs.antibody \
#	nixpkgs.git \
#	nixpkgs.neovim \
#	nixpkgs.tmux \
#	nixpkgs.stow \
#	nixpkgs.yarn \
#	nixpkgs.fzf \
#	nixpkgs.ripgrep \
#	nixpkgs.bat \
#	nixpkgs.gnumake \
#	nixpkgs.gcc \
#	nixpkgs.direnv

# stow dotfiles
#stow git
#stow nvim
#stow tmux
#stow zsh

# add zsh as a login shell
#command -v zsh | sudo tee -a /etc/shells

# use zsh as default shell
#sudo chsh -s $(which zsh) $USER

# bundle zsh plugins
#antibody bundle < ~/.zsh_plugins.txt > ~/.zsh_plugins.sh

# install neovim plugins
#nvim --headless +PlugInstall +qall

# Use kitty terminal on MacOS
[ `uname -s` = 'Darwin' ] && stow kitty


# Create symlinksß

ln -s ~/.dotfiles/.vimrc ~/.vimrc
ln -s ~/.dotfiles/.viminfo ~/.viminfo
ln -s ~/.dotfiles/.bashrc ~/.bashrc
ln -s ~/.dotfiles/.bash_profile ~/.bash_profile
ln -s ~/.dotfiles/.bash_login ~/.bash_login
ln -s ~/.dotfiles/.bash_logout ~/.bash_logout
ln -s ~/.dotfiles/.zshrc ~/.zshrc
ln -s ~/.dotfiles/.gitconfig ~/.gitconfig
ln -s ~/.dotfiles/.gitignore_global ~/.gitignore_global

if [ "$(uname)" == "Darwin" ]; then
    ln -s /Users/julianwest/.dotfiles/.vscode/settings.json /Users/julianwest/Library/Application\ Support/Code/User/settings.json
    ln -s /Users/julianwest/.dotfiles/.vscode/keybindings.json /Users/julianwest/Library/Application\ Support/Code/User/keybindings.json
    ln -s /Users/julianwest/.dotfiles/.vscode/snippets/ /Users/julianwest/Library/Application\ Support/Code/User
else

fi

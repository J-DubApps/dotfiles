# JDub's .bashrc

# allow to omit 'cd' to change directories
shopt -s autocd

#########################################
# DOCKER
#########################################
alias dlist="docker ps -a"
docker_ids() { docker ps -aq; }
docker_stop_all() { docker stop $(docker_ids); }
docker_remove_all() { docker rm $(docker_ids); }

alias ls='ls -C -G --color=auto'
alias l='ls'
alias ll='ls -hl'
alias la='ll -A'
alias suspend='zzz'
alias hibernate='ZZZ'
alias clr='clear'
alias fetch='neofetch'
#alias scrot="scrot -q 100 -e 'mv $f ~/Pictures/Screenshots'"

# xbps aliases
alias install='sudo xbps-install -Sv'
alias ins='sudo xbps-install -Sv'
alias update='sudo xbps-install -Suv'
alias upd='sudo xbps-install -Suv'
alias clean='sudo xbps-remove -oORv'
alias cln='sudo xbps-remove -oORv'
alias remove='sudo xbps-remove -Rv'
alias rmp='sudo xbps-remove -Rv'
alias packages='xbps-query -l'
alias pkgs='xbps-query -l'
alias search='xbps-query -Rs'
alias srch='xbps-query -Rs'

# git aliases
alias pull='git pull'
alias push='git push'
alias fetch='git fetch'
alias rebase='git rebase'

alias lg='lazygit'

alias wlan='nmcli dev wifi list'
alias wlan-rescan='nmcli dev wifi rescan'
alias irc='weechat'
#alias vi='nvim'
#alias vim='nvim'
alias gs="git status"
alias gsl="git stash list"
alias gc="git checkout"
alias gcp="git cherry-pick"
alias gb="git branch"
alias guc="git reset HEAD~"
alias h="history"
alias ch='history | grep "git commit"'
alias home='cd ~/'
alias gp="git fetch origin --prune"

# clean up branches that no longer exist on origin off local
alias cb="git remote prune origin && git branch -vv | grep '\[[^]]* gone]' | awk '{ print $1 }' | xargs git branch -D"
alias startpost="pg_ctl -D ~/.asdf/installs/postgres/9.6.8/data -l logfile start"
alias stoppost="pg_ctl -D ~/.asdf/installs/postgres/9.6.8/data stop -s -m fast"
alias profile="open ~/.bash_profile"
alias containers="docker ps -a"
alias pgreload="pg_ctl reload"
alias reload="source ~/.bash_profile"

scon() {
  docker stop `docker ps -aq`
}

rmcon() {
  docker rm `docker ps -aq`
}

sig () {
  declare -f "$1"
}

# Project helpers

alias ..='cd ../'                      # Go back 1 directory level
alias ...='cd ../../'                  # Go back 2 directory levels
alias .3='cd ../../../'                # Go back 3 directory levels
alias .4='cd ../../../../'             # Go back 4 directory levels
alias .5='cd ../../../../../'          # Go back 5 directory levels
alias .6='cd ../../../../../../'       # Go back 6 directory levels
alias c='clear'                        # Clear terminal display
alias path='echo -e ${PATH//:\\\n}'    # Echo all executable Paths
alias edit='open -a TextEdit'   # open using TextEdit
alias l='ls -altr'                      # list all in order

# List all files colorized in long format, including dot files
alias la="ls -lahF ${colorflag}"

# Show/hide hidden files in Finder
alias show="defaults write com.apple.finder AppleShowAllFiles -bool true && killall Finder"
alias hide="defaults write com.apple.finder AppleShowAllFiles -bool false && killall Finder"

searchAndDestroy() {

  lsof -i TCP:$1 | grep LISTEN | awk '{print $2}' | xargs kill -9

  echo "Port" $1 "found and killed."

}

searchProfile() {
  cat ~/.bash_profile | grep $1
}

#Delete remote branch and local branch

gd() {
  confirm "Force delete $(curbranch) on both your local machine AND origin?" && git push origin --delete $1 && gb -D $1
}

gsp() {
  git stash push -u -m $1;
  echo "Stash created with name" $1
}

#Delete local branch

gdl() {

  gb -D $1

}

#alias groups='/etc/groups'
#alias sudoers='/etc/sudoers'

git_info() {
	curr_branch=$(git rev-parse --abbrev-ref HEAD 2> /dev/null);
	curr_remote=$(git config branch.$curr_branch.remote);
	curr_merge_branch=$(git config branch.$curr_branch.merge | cut -d / -f 3)
	ahead_behind=$(git rev-list --left-right --count $curr_remote/$curr_merge_branch...$curr_branch 2> /dev/null | sed -e 's/\([0-9]\)/↓\1/1' -e 's/\([0-9]\)/↑\1/2')
	( echo -n $curr_branch || echo -n " "; echo -n $ahead_behind; ) | sed 's/\(.*\)\(↓.*\)/─( \1 \2)/'
}

set -o vi
PS1='\n┌[\e[1;39m\u\e[m@\e[1;31m\h\e[m]─[\e[1;34m\w\e[m]$(git_info)\nλ '
#╼
bind 'set show-mode-in-prompt on'
bind 'set vi-ins-mode-string └[\1\e[0;32m\2i\1\e[m\2]'
bind 'set vi-cmd-mode-string └[\1\e[0;34m\2c\1\e[m\2]'

if command -v starship &> /dev/null
then
	bind 'set show-mode-in-prompt off'
	eval "$(starship init bash)"
fi

# . "$HOME/.cargo/env"

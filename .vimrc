""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"                                 JDub's vimrc                                 "
"                                                                              "
"                                 	                           				   "
"                            						                           "
"                                                                              "
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" Copy or symlink to ~/.vimrc or ~/_vimrc.

set nocompatible                  " Must come first because it changes other options.

"set termguicolors                 " Enable 24-bit RGB colors.

silent! call pathogen  # runtime_append_all_bundles()

syntax enable                    " Turn on syntax highlighting.
filetype plugin indent on         " Turn on file type detection.

runtime macros/matchit.vim       " Load the matchit plugin.

set showcmd                       " Display incomplete commands.
set showmode                      " Display the mode you're in .

set backspace=indent,eol,start " Intuitive backspacing.

set hidden                        " Handle multiple buffers better.

set wildmenu                      " Enhanced command line completion.
set wildmode=list:longest,full         " Complete files like a shell.

set ignorecase                    " Case-insensitive searching.
set smartcase                     " But case-sensitive if expression contains a capital letter.

set number                        " Show line numbers.
set ruler                         " Show cursor position.

set incsearch                     " Highlight matches as you type.
set hlsearch                      " Highlight matches.

set wrap                          " Turn on line wrapping.
set scrolloff=3                   " Show 3 lines of context around the cursor.

set title                         " Set the terminal's title

set visualbell                    " No beeping.

set nobackup                      " Don't make a backup before overwriting a file.
set nowritebackup                 " And again.
set directory=$HOME/.vim/tmp//    " Keep swap files in one location

" UNCOMMENT TO USE
"set tabstop=2                    " Global tab width.
"set shiftwidth=2                 " And again, related.
"set expandtab                    " Use spaces instead of tabs

set laststatus=2                  " Show the status line all the time
" Useful status information at bottom of screen
set statusline=[%n]\ %%<%.99f\ %h%w%m%r%y\ %{fugitive#statusline()}%{exists('*CapsLockStatusline')?CapsLockStatusline():''}%=%-16(\ %l,%c-%v\ %)%P

" Or use vividchalk
colorscheme topfunky-light

" Tab mappings.
map < leader > tt: tabnew < cr >
map < leader > te: tabedit
map < leader > tc: tabclose < cr >
map < leader > to: tabonly < cr >
map < leader > tn: tabnext < cr >
map < leader > tp: tabprevious < cr >
map < leader > tf: tabfirst < cr >
map < leader > tl: tablast < cr >
map < leader > tm: tabmove

" Using arrow keys is far too ingrained in my muscle memory
" This is to force my hand
map <up> <nop>
map <down> <nop>
map <left> <nop>
map <right> <nop>
imap <up> <nop>
imap <down> <nop>
imap <left> <nop>
imap <right> <nop>

" Uncomment to use Jamis Buck's file opening plugin
"map < Leader > t: FuzzyFinderTextMate < Enter >

" Controversial...swap colon and semicolon for easier commands
"nnoremap;:
"nnoremap:;

"vnoremap;:
"vnoremap:;

" Automatic fold settings for specific files. Uncomment to use.
" autocmd FileType ruby setlocal foldmethod = syntax
" autocmd FileType css  setlocal foldmethod = indent shiftwidth = 2 tabstop = 2

" For the MakeGreen plugin and Ruby RSpec. Uncomment to use.
autocmd BufNewFile, BufRead * _spec.rb compiler rspec

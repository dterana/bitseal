#compdef casemate

_casemate() {
  local -a common
  common=(
    '*-file[input file, repeatable]:file:_files'
    '-out[output file]:file:_files'
    '-password-file[read the password from a file]:file:_files'
    '-password-env[read the password from an environment variable]:name:'
    '-password-fd[read the password from a file descriptor]:fd:'
    '-keyfile[use a key file as a second factor]:file:_files'
    '-strict[turn password warnings into errors]'
  )

  if (( CURRENT == 2 )); then
    local -a cmds
    cmds=(
      'encrypt:encrypt files or directories'
      'decrypt:decrypt files'
      'rekey:re-encrypt files in place'
      'info:show a file format without decrypting'
      'keygen:create a random key file'
      'version:show version information'
      'help:show usage'
    )
    _describe 'command' cmds
    return
  fi

  case $words[2] in
    encrypt) _arguments $common '*:file:_files' ;;
    decrypt) _arguments $common '-extract[unpack a directory archive]' '*:file:_files' ;;
    rekey)
      _arguments $common \
        '-change-password[prompt for a new password]' \
        '-new-password-file[read the new password from a file]:file:_files' \
        '-new-password-env[read the new password from an environment variable]:name:' \
        '-new-password-fd[read the new password from a file descriptor]:fd:' \
        '-new-keyfile[set or replace the key file]:file:_files' \
        '-no-keyfile[remove the key file requirement]' \
        '-recursive[rekey every encrypted file under a directory]' \
        '-dry-run[list what would be rekeyed without writing]' \
        '*:file:_files'
      ;;
    info) _arguments '*-file[input file, repeatable]:file:_files' '-json[print JSON]' '*:file:_files' ;;
    keygen) _arguments '-out[where to write the key file]:file:_files' ;;
  esac
}

_casemate "$@"

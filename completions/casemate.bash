# bash completion for casemate
_casemate() {
  local cur prev cmd
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd="${COMP_WORDS[1]}"

  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=($(compgen -W "encrypt decrypt rekey info keygen version help" -- "$cur"))
    return
  fi

  case "$prev" in
    -file|-out|-password-file|-keyfile|-new-password-file|-new-keyfile)
      COMPREPLY=($(compgen -f -- "$cur"))
      return
      ;;
  esac

  local common="-file -out -password-file -password-env -password-fd -keyfile -strict"
  case "$cmd" in
    encrypt) COMPREPLY=($(compgen -W "$common" -- "$cur")) ;;
    decrypt) COMPREPLY=($(compgen -W "$common -extract" -- "$cur")) ;;
    rekey)   COMPREPLY=($(compgen -W "$common -change-password -new-password-file -new-password-env -new-password-fd -new-keyfile -no-keyfile -recursive -dry-run" -- "$cur")) ;;
    info)    COMPREPLY=($(compgen -W "-file -json" -- "$cur")) ;;
    keygen)  COMPREPLY=($(compgen -W "-out" -- "$cur")) ;;
  esac
  if [ ${#COMPREPLY[@]} -eq 0 ]; then
    COMPREPLY=($(compgen -f -- "$cur"))
  fi
}
complete -F _casemate casemate

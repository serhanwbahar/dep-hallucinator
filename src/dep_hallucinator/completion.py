"""
Shell completion scripts.
"""

from typing import Dict


def get_bash_completion() -> str:
    """Bash completion script."""
    return """
# Bash completion for dep-hallucinator
_dep_hallucinator_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    if [[ ${COMP_CWORD} == 1 ]]; then
        opts="scan batch info config --version --help"
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
    
    if [[ "${COMP_WORDS[1]}" == "config" && ${COMP_CWORD} == 2 ]]; then
        opts="init show validate"
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
    
    if [[ "${COMP_WORDS[1]}" == "scan" || "${COMP_WORDS[1]}" == "batch" ]]; then
        case "${prev}" in
            --output-file|-o|--output-dir)
                COMPREPLY=( $(compgen -f -- ${cur}) )
                return 0
                ;;
            --output-format)
                COMPREPLY=( $(compgen -W "console json" -- ${cur}) )
                return 0
                ;;
            *)
                local files=$(find . -maxdepth 2 -name "requirements*.txt" -o -name "package.json" 2>/dev/null | head -20)
                COMPREPLY=( $(compgen -W "${files}" -- ${cur}) )
                return 0
                ;;
        esac
    fi
}

complete -F _dep_hallucinator_completion dep-hallucinator
"""


def get_zsh_completion() -> str:
    """Zsh completion script."""
    return """
#compdef dep-hallucinator

_dep_hallucinator() {
    local context state state_descr line
    typeset -A opt_args
    
    _arguments -C \
        '1: :_dep_hallucinator_commands' \
        '*:: :->args'
    
    case $state in
        args)
            case $words[1] in
                scan)
                    _arguments \
                        '--rate-limit[API requests per second limit]:rate limit:(1 5 10 20)' \
                        '--max-concurrent[Maximum concurrent registry checks]:max concurrent:(5 10 20 50)' \
                        '--output-format[Output format]:format:(console json)' \
                        '--output-file[Save results to file]:file:_files' \
                        '--quiet[Suppress non-critical output]' \
                        '--verbose[Enable verbose output]' \
                        '--fail-on-high[Exit with error code if HIGH risk packages found]' \
                        '*:dependency file:_dep_hallucinator_files'
                    ;;
                batch)
                    _arguments \
                        '--rate-limit[API requests per second limit]:rate limit:(1 5 10 20)' \
                        '--max-concurrent[Maximum concurrent registry checks]:max concurrent:(5 10 20 50)' \
                        '--output-format[Output format]:format:(console json)' \
                        '--output-dir[Directory to save results]:directory:_directories' \
                        '--quiet[Suppress non-critical output]' \
                        '--verbose[Enable verbose output]' \
                        '*:dependency files:_dep_hallucinator_files'
                    ;;
                config)
                    _arguments '1: :(init show validate)'
                    ;;
            esac
            ;;
    esac
}

_dep_hallucinator_commands() {
    local commands
    commands=(
        'scan:Scan a dependency file for vulnerabilities'
        'batch:Scan multiple dependency files'
        'info:Show information about supported file types'
        'config:Configuration management commands'
    )
    _describe 'command' commands
}

_dep_hallucinator_files() {
    local files
    files=($(find . -maxdepth 2 \\( -name "requirements*.txt" -o -name "package.json" \\) 2>/dev/null))
    _multi_parts / files
}

_dep_hallucinator "$@"
"""


def get_fish_completion() -> str:
    """Fish completion script."""
    return """
# Fish completion for dep-hallucinator

complete -c dep-hallucinator -n '__fish_use_subcommand' -a 'scan' -d 'Scan a dependency file'
complete -c dep-hallucinator -n '__fish_use_subcommand' -a 'batch' -d 'Scan multiple files'
complete -c dep-hallucinator -n '__fish_use_subcommand' -a 'info' -d 'Show information'
complete -c dep-hallucinator -n '__fish_use_subcommand' -a 'config' -d 'Configuration management'
complete -c dep-hallucinator -n '__fish_use_subcommand' -l version -d 'Show version'
complete -c dep-hallucinator -n '__fish_use_subcommand' -l help -d 'Show help'

complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan' -l rate-limit -d 'API requests per second' -x
complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan' -l max-concurrent -d 'Max concurrent requests' -x
complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan' -l output-format -d 'Output format' -x -a 'console json'
complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan' -l output-file -d 'Output file' -F
complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan' -l quiet -d 'Quiet mode'
complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan' -l verbose -d 'Verbose mode'
complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan' -l fail-on-high -d 'Fail on high risk'

complete -c dep-hallucinator -n '__fish_seen_subcommand_from batch' -l rate-limit -d 'API requests per second' -x
complete -c dep-hallucinator -n '__fish_seen_subcommand_from batch' -l max-concurrent -d 'Max concurrent requests' -x
complete -c dep-hallucinator -n '__fish_seen_subcommand_from batch' -l output-format -d 'Output format' -x -a 'console json'
complete -c dep-hallucinator -n '__fish_seen_subcommand_from batch' -l output-dir -d 'Output directory' -x -a "(__fish_complete_directories)"
complete -c dep-hallucinator -n '__fish_seen_subcommand_from batch' -l quiet -d 'Quiet mode'
complete -c dep-hallucinator -n '__fish_seen_subcommand_from batch' -l verbose -d 'Verbose mode'

complete -c dep-hallucinator -n '__fish_seen_subcommand_from config' -a 'init' -d 'Create sample config'
complete -c dep-hallucinator -n '__fish_seen_subcommand_from config' -a 'show' -d 'Show current config'
complete -c dep-hallucinator -n '__fish_seen_subcommand_from config' -a 'validate' -d 'Validate config file'

complete -c dep-hallucinator -n '__fish_seen_subcommand_from scan batch' -x -a "(find . -maxdepth 2 \\( -name 'requirements*.txt' -o -name 'package.json' \\) 2>/dev/null)"
"""


def get_completion_scripts() -> Dict[str, str]:
    """Return all completion scripts."""
    return {
        "bash": get_bash_completion(),
        "zsh": get_zsh_completion(),
        "fish": get_fish_completion(),
    }

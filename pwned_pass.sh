#!/usr/bin/env bash

set -euo pipefail

prog=$(basename "$0")

msg() { echo "$@" >&2 ;}

print_usage() {
    msg "${prog}"
    msg
    msg '  -h, --help      print this help text and exit'
    msg '  -q, --quiet     suppress non-essential output'
    msg
}

prompt() {
    if (( quiet == 0 )); then
        msg
        msg -n 'Type a password and hit Enter (leave empty to exit): '
    fi
}

wipe_password_var() {
    # obfuscate plaintext password, appeasing Bash by removing null characters
    password=$(head -c 256 /dev/urandom | tr '\0' 'x')
    unset password
}

download_response() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS "$1"
    else
        wget -qO- "$1"
    fi
}

get_password_hash() {
    local temp_hash

    if command -v sha1sum >/dev/null 2>&1; then
        temp_hash="$(echo -n "${password}" | sha1sum)"
        temp_hash="${temp_hash%-}"
        echo "${temp_hash%"${temp_hash##*[![:space:]]}"}"
    elif command -v openssl >/dev/null 2>&1; then
        temp_hash="$(echo -n "${password}" | openssl sha1)"
        echo "${temp_hash#SHA1(stdin)= }"
    fi
}

check_if_pwned() {
    # ${password} is a global variable so we can easily wipe it via a Bash trap
    local password_hash
    local hash_prefix
    local hash_suffix
    local count
    local api_url

    password_hash="$(get_password_hash)"

    wipe_password_var

    hash_prefix="${password_hash:0:5}"
    hash_suffix="${password_hash:5}"
    api_url="https://api.pwnedpasswords.com/range/${hash_prefix}"

    if (( quiet == 0 )); then
        msg "Hash prefix: ${hash_prefix}"
        msg "Hash suffix: ${hash_suffix}"
        msg
        msg 'Looking up your password...'
    fi

    local count_line
    if count_line="$(download_response "${api_url}" | grep -i "${hash_suffix}")"; then
        IFS=':' read -r _ count <<< "${count_line}"
    else
        count=0
    fi

    if (( quiet == 0 )); then
        msg "Your password appears in the Pwned Passwords database ${count} time(s)."

        if (( count >= 100 )); then
            msg 'Your password is thoroughly pwned! DO NOT use this password for any reason!'
        elif (( count >= 20 )); then
            msg 'Your password is pwned! You should not use this password!'
        elif (( count > 0 )); then
            msg 'Your password is pwned, but not ubiquitous. Use this password at your own risk!'
        elif (( count == 0 )); then
            msg "Your password isn't pwned, but that doesn't necessarily mean it's secure!"
        fi
    else
        msg "${password_hash}    ${count}"
    fi

}

trap wipe_password_var EXIT

quiet=0
for arg in "$@"; do
    case "${arg}" in
        -h|--help)
            print_usage
            exit 0
            ;;
        -q|--quiet)
            quiet=1
            ;;
        *)
            print_usage
            msg "Unrecognized argument: '${arg}'"
            msg 'Note: For security reasons, this script no longer accepts passwords via command-'
            msg 'line arguments. Please use the prompt or pipe a file into this script.'
            exit 1
            ;;
    esac
done

if (( quiet == 0 )); then
    msg
    msg 'REMINDER: This tool does not check password strength!'
fi
prompt

while read -rs password; do
    [[ -n ${password} ]] || exit 0
    (( quiet == 1 )) || msg
    check_if_pwned
    prompt
done < /dev/stdin

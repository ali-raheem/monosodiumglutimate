# Mono Sodium Glutimate

Simple utility using libsodium to sign strings. Goal is to be simple enough that code is reviewable in under an hour.

## Usage

Generate keys with `msg generate`, then export them with `msg export`. Sign with `msg sign "MESSAGE TEXT HERE"`. Finally you can verify with `msg sign "MESSAGE TEXT HERE" SIGNATURE PUBLIC_KEY`

## Building

Depends on libsodium, `gcc -o msg -lsodium src/msg.c`

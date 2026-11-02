Monocypher 4.0.2 (https://monocypher.org), BSD-2-Clause or CC0, see LICENCE.md. Unmodified, except that the
`.c` files are named `.c.inc`: airplay_curve25519.cpp compiles them as C++ in a namespace of their own, so that
their `crypto_*` functions cannot clash with libsodium or another copy of Monocypher in the same firmware.

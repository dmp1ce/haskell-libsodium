Change log
==========

libsodium uses [Semantic Versioning][1].
The change log is available [on GitHub][2].

[1]: http://semver.org/spec/v2.0.0.html
[2]: https://github.com/dmp1ce/haskell-libsodium/releases

## v0.1.0.0

* Add functions from LibSodium documenation with tests
  * sodium_init
  * sodium_memcmp
  * sodium_bin2hex
  * sodium_hex2bin
  * sodium_increment
  * sodium_add
  * sodium_compare
  * sodium_is_zero
  * sodium_memzero
  * sodium_mlock
  * sodium_munlock
  * sodium_malloc
  * sodium_allocarray
  * sodium_free
  * sodium_mprotect_noaccess
  * sodium_mprotect_readonly
  * sodium_mprotect_readwrite
  * randombytes_random
  * randombytes_uniform
  * randombytes_buf
  * randombytes_close
  * randombytes_stir
* Initially created.

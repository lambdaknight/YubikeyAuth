# YubikeyAuth
Yubikey authentication library for OS X.

# Building hyubikey
```
cd hyubikey
cabal install --dependencies-only
cabal configure
cabal build
```

This will build the library as well as a SO that is usable with PAM. The files will be located in dist/build somewhere.

After it is built, the following can be run to run a really basic set of test cases:
```
cabal run -- -t
```

# Building HYubikeyAuth

Work in progress. Can be accomplished by manually including the *.a files in hyubikey/dist/build in the Xcode project.

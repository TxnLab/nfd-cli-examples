# nfd-cli-examples

Simple examples of on-chain NFD operations using standalone Go command-line programs

## Go language
* See: https://go.dev/ for information and to install the compiler with very simple install.  Homebrew is also supported if you want to install that way.

## Programs
### nfd-display
  * This example can lookup an NFD by name, or by address completely on-chain (using algonode nodes as an example), and also display the metadata in json.  Properties are converted/merged as NFDomains expects.
  * This is a minimal example but provides the bulk of the on-chain mechanics for referencing of NFDs.

## Running the code
* For each binary, you can compile/run in one step using 'go run'
* Using nfd-display as an example:
  ```shell
  cd nfd-display 
  go run ./main.go -name nfdomains.algo 
  ```

## Compiling the code
* You can compile the code, using: `go install` - This will place a standalone compiled binary into the go/bin directory off of your home directory (ie: your $HOME directory on osx/linux and equivalent on Windows).
* You can also run `go build .` inside the program directory to place the generated binary in the same directory.

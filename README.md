iptrie

Simple trie implementation, heavily influenced by @postwait's https://github.com/postwait/node-iptrie/blob/master/src/btrie.cc

In order to keep things fast it fixes number of bits used by nodes. It also uses unsafe.Pointer to hint location of a value since trees often used to index structures living in other memory area. This is both good and bad since:

1. you can store anything without paying size/performance penalty of the interface{} type
2. you move values on a tree very efficiently (even more tricks are possible, there is no time to code them as examples)
3. you got to think about garbage collection and unsafe.Pointer type working in concert, compiler is just doing what it thinks is right.

In order to generate code for different number of bits than default ones in tree_auto.go you need to change tree_generate.go and re-run `go generate` command.  By default generaged tree_auto.go already includes 32, 64, 128 bit trie implementations.


THIS IS DEMO PROTOTYPE. SORRY FOR LIMITED COMMENTS AND ABSENSE OF A USAGE GUIDE.

Use at your own risk.

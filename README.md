# iptrie

Simple trie implementation, heavily influenced by @postwait's https://github.com/postwait/node-iptrie/blob/master/src/btrie.cc

Other documented libs that do similar things to make sense of purpose of this project (storing map of CIDR:value entries)
* http://search.cpan.org/~cvicente/Net-IPTrie-0.7/lib/Net/IPTrie.pm
* https://pypi.python.org/pypi/patricia-trie

If you use only ipv4 and all addresses you look up are /32 you still should get reasonably fast mapping but it's recommended to look in other tree implementations as well. 

In order to keep things fast it fixes number of bits used by nodes. It also uses unsafe.Pointer to hint location of a value since trees often used to index structures living in other memory area. This is both good and bad since:

1. you can store anything without paying size/performance penalty of the interface{} type
2. you move values on a tree very efficiently (even more tricks are possible, there is no time to code them as examples)
3. you got to think about garbage collection and unsafe.Pointer type working in concert, compiler is just doing what it thinks is right.

In order to generate code for different number of bits than default ones in tree_auto.go you need to change tree_generate.go and re-run `go generate` command.  By default generaged tree_auto.go already includes 32, 64, 128 bit trie implementations.


THIS IS DEMO PROTOTYPE. SORRY FOR LIMITED COMMENTS AND ABSENSE OF A USAGE GUIDE.

Use at your own risk. Don't forget mutexes for operations that change tree structure.

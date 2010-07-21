# triptools

This is a collection of [tripcode](http://en.wikipedia.org/wiki/Tripcode)-related command line utilities. All of them require OpenSSL (`libssl-dev` on Debian and Ubuntu), and have only been tested on Linux.


## `tripcode`

The first tool is `tripcode`, which just applies the tripcode algorithm to its arguments. It does Shiichan-style character escaping, which may or may not be what you want.

By default, input is converted to SJIS, and it is assumed to be in UTF-8 before conversion. If you don't want it to be converted, compile it without defining SJIS_CONVERT. If your character encoding isn't UTF-8, you will have to edit `tripcode.c`.

### Usage example

>     $ ./tripcode tea 1fXzap//
>     WokonZwxw2
>     MhMRSATORI


## `tripfind`

The second is a tripcode searcher. It takes an argument and starts a number of processes (one by default) to search for occurences of that string in tripcodes.

To ensure maximum compatibility, the search space does not include characters which may or may not be escaped (ampersands, quotes, angle brackets) or characters affected by different character encodings (anything outside of ASCII).

In principle, the processes run until they've exhausted their search space. In practice you'll want to interrupt them with a `SIGINT` when you're tired of waiting.

### Usage example

>     $ ./tripfind -p 2 Xarn
>     [20289] Starting at !.
>     [20288] Starting at R.
>     !!!!$4jo -> mHsoRXarng
>     !!!!%W8Z -> 7ilpUXarng
>     !!!!%oU: -> pXarnc2R2A
>     !R!!(~Sy -> EKkXarnS7w
>     !!!!)2]s -> /iXarnEb2w^C
>     [20288] 4181336 tripcodes examined in 26.219 seconds (160820 per second).
>     [20289] 4081334 tripcodes examined in 26.276 seconds (156974 per second).


## `sectrip` and `secfind`

These are the equivalents of `tripcode` and `tripfind` for Shiichan's secure tripcode algorithm. Their usage is identical to their regular equivalents.

**Caveat:** these depend on a secret salt, which, inconveniently, isn't known for world4ch. These tools currently use an old salt that was compromised and replaced. Less than useful, sorry.


## `tripfind-regex` and `secfind-regex`

These are equivalent to `tripfind` and `secfind`, except that instead of a simple string, they take a POSIX extended regular expression for a target. This makes them slightly slower.


## `build.sh`

This isn't actually one of the tools, but just a helper script that will invoke `make` to build the utilities, and will also test the output of `tripcode` and `sectrip` to ensure that it's consistent with known tripcodes.

If you don't want to build all four tools at once, you can also build them individually using `make tripcode`, `make tripfind`, &c.

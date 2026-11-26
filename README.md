# SIP Lens

I work in VoIP support. Most days start with the same question: why did this call fail?

The answer is almost always in the SIP trace, somewhere in a few hundred lines of packets. If you've read a lot of traces you know where to look. If you haven't, it's a wall of text, and the ticket gets escalated.

SIP Lens is my attempt to close that gap. You give it a trace and it tells you what went wrong in plain language, shows you the lines that prove it, and suggests what to try first. The full call is still there as a diagram and as raw messages, for when you want to check its reasoning.

It runs entirely in the browser. Traces are full of phone numbers and IP addresses, so nothing gets uploaded anywhere.

> This is an early version, so expect rough edges. If it gets something wrong, I'd like to know.

## What it can spot so far

I started with the failures I see most often at work:

- **One-way audio.** The phone puts a private address (192.168.x.x and friends) in its SDP while sitting behind NAT, so the audio coming back never reaches it.
- **Codec mismatch.** A `488 Not Acceptable Here` because the two sides have no audio format in common. It lists what was actually offered.
- **Authentication loop.** `401` or `407` again and again even though the phone is sending credentials. Usually a wrong password or auth ID.
- **Calls dropping after about 32 seconds.** The `200 OK` keeps being resent because its ACK never arrives. Very often NAT again.
- **Rejected calls.** `404`, `403`, `486`, `503` and others, each explained in normal words. For a 404 it also checks whether the number went out without a country code.

Every diagnosis comes with the evidence behind it. If it says the problem is on line 15 of message 1, you can open message 1 and look at line 15.

## Trying it

There's nothing to install. Download or clone the repo and open `index.html` in your browser.

The page has sample traces for each case above, plus a capture of the one-way audio call with its audio included. They use made-up numbers and the IP ranges reserved for documentation.

To use your own trace, drop in a .pcap or .pcapng capture, or paste the SIP messages as text.

With a capture it also counts the audio (RTP) streams, so for one-way audio it doesn't have to guess: it can show the packets going to an address that can't be reached, or tell you the server is already handling NAT and the problem is somewhere else.

For text, it reads a .txt file or whatever you paste. If each message has a line with its addresses before it, like the ones ngrep and sngrep write, you also get the call diagram:

```
U 2026/11/26 10:15:02.000000 203.0.113.24:41872 -> 198.51.100.10:5060
INVITE sip:+351212345142@sbc.example.net SIP/2.0
Via: SIP/2.0/UDP 192.168.1.45:5060;branch=z9hG4bK3f1a9c;rport
...
```

`ngrep -W byline port 5060` gives you that format straight away.

## About privacy

- The page doesn't make any network requests, not even for fonts.
- "Anonymise" is on by default. Phone numbers in SIP URIs are masked and public IPs are swapped for placeholder ones, always the same replacement for the same address so the diagram still reads correctly. Private addresses are left alone, because they're often the whole point.

## How it's put together

Plain HTML, CSS and JavaScript, no framework and no build step.

```
index.html              the page
styles.css
src/parser.js           turns trace text into messages, headers and SDP
src/pcap.js             reads .pcap/.pcapng files: SIP messages and RTP streams
src/rules.js            one function per failure it can recognise
src/app.js              diagnosis, call diagram, list and message views
src/samples.js          generated from samples/*.txt
samples/                example traces
test/run.js             tests, run with Node
tools/build-samples.js  rebuilds src/samples.js after you edit a sample
tools/make-pcap.js      builds the sample capture from a text trace
```

Running the tests (needs Node.js):

```
node test/run.js
```

Each rule in `src/rules.js` gets one call at a time and either returns a finding or nothing. To add a new one, write the function, add it to the list at the bottom, and add a sample trace and a test for it.

## Accessibility

The call diagram also has a list view with the same information, for screen readers and keyboards. Failures are marked with a label and a shape, not just a colour. I'm aiming for WCAG 2.2 AA.

## What's next

- SIP over TCP split across several segments (for now each segment is read on its own)
- Audio quality from RTP: packet loss and jitter, not just whether audio arrives
- More cases: hold and re-INVITE problems, session timers, early media
- A shareable report of a diagnosis

Feedback from anyone who reads SIP traces for a living is very welcome. Open an issue if it gets something wrong.

## Licence

MIT

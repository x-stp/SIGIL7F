SIGIL7F  
=========

A symbolic MIDI dissector and event mutator.  
Written in Go. No dependencies. Parses like bone, walks like trace.  
This isn’t sound — it’s structure. You want the sigil? You read the glyphs.

---

What it does  
------------

- Parses SMF (Standard MIDI File) Type 0, 1, 2
- Reads delta-time via VLQ decoding
- Dumps MIDI, Meta, and SysEx events
- Reconstructs valid byte-aligned `.mid` files
- Handles running status, malformed sequences
- Built for fuzzing, symbolic fault injection, cursed track mutation

---

Use cases  
---------

- Inspection of embedded playback triggers
- MIDI fuzzing for real-time systems
- Fault propagation testing across channels
- Crafting hostile `.mid` payloads
- Feeding broken glyphs into anything that dares parse tempo

---

Example  
-------

```go
mf := MIDIFile{}
if err := mf.Parse(data); err != nil {
	log.Fatal("glyph unrecognized")
}

for _, g := range mf.Tracks[0].Events {
	if g.Type == Meta && g.Meta.Type == 0x2F {
		fmt.Println("end of track – sigil sealed")
	}
}

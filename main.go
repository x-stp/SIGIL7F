// package main -- yeah, 'main'. whatever that means for this... thing.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	// "time" // time? ha. this code operates on its own damn timeline. no kernel tick-tock here.
)

// --- core directives & schematics :: or so they're labeled ---
// these ain't just numbers. they're whispers. fixed points in the chaos stream.
const (
	// chunk signatures - ancient glyphs burned into the protocol
	SigilMThd = "MThd" // mthd... the master header sigil. they say it's key. always these four.
	SigilMTrk = "MTrk" // mtrk... track chunk sigil. marks a signal sequence. or a trap.

	// header block dimensions - measures of a forgotten architecture
	GlyphHeaderFixedSize = 0xE // 0xe. static header size. why 0xe? a magic number? or just... 14.
	GlyphHeaderDataSize  = 0x6 // expected payload size here. 6 bytes. usually. don't trust it completely.

	// track chunk dimensions - paths through a data maze
	GlyphTrackHeaderFixedSize = 0x8 // static track header. 8 bytes. another 'sacred' number?

	// meta signal glyphs - encrypted orders from... somewhere else
	GlyphMetaSignalStatus = 0xFF // 0xff. meta-signal status. means the rules are changing. watch out.
	GlyphEndOfTrack       = 0x2F // 0x2f. end of track. that's what it *wants* you to think. e.o.t.

	// sysex signal glyphs - raw machine code. direct hardware injection. scary.
	GlyphSysExStart = 0xF0 // 0xf0. sysex start. the machine stirs.
	GlyphSysExEnd   = 0xF7 // 0xf7. sysex end. or so it claims. f7 is... fickle. could be a continuation.

	// numeric masks & shifts - keys to some old compression cipher? (vlq, they call it)
	MaskVLQByte       = 0x7F // 0x7f. to get the 7-bit heart from a vlq byte.
	FlagVLQContinue   = 0x80 // 0x80. the 'more coming' flag in a vlq. it never ends.
	ShiftVLQ          = 0x7  // 7. the astral shift for vlq assembly. align the damn bits.
	MaskStatusType    = 0xF0 // 0xf0. to guess the signal's core function.
	MaskStatusChannel = 0x0F // 0x0f. to find the signal's channel. if it has one.
	FlagIsStatusByte  = 0x80 // 0x80. marks a true status byte. not just noise. a command. maybe.
)

// --- variable length quantity (vlq) engine :: black magic, probably ---

// decodevlqpayload unpacks a number from the stream. how the fuck does it know how long it is?
// data stream -> numerical glyph. they say.
// returns: new offset, the glyph, and if the stream just... broke.
func decodeVLQPayload(dataStream []byte, currentOffset int) (offsetAfter int, glyph uint32, corruption error) {
	var numericalGlyph uint32 = 0x0
	offset := currentOffset
	var currentPayloadByte byte // the soul of the current byte, or just bits.

	// a vlq... it's supposed to be 4 bytes max in midi. if it's longer, the data's fubar. or a new trick.
	for i := 0x0; i < 0x4; i++ { // the four horsemen of vlq. cute.
		if offset >= len(dataStream) {
			corruption = errors.New("stream just... died. mid-vlq. typical.")
			return offset, numericalGlyph, corruption
		}
		currentPayloadByte = dataStream[offset]
		numericalGlyph = (numericalGlyph << ShiftVLQ) | uint32(currentPayloadByte&MaskVLQByte) // weave the 7-bit essence. or whatever.
		offset++
		if (currentPayloadByte & FlagVLQContinue) == 0x0 { // the last byte. the pattern completes. or so it seems.
			return offset, numericalGlyph, nil
		}
	}
	// loop finished? means the vlq is a monster. deep corruption. shadowbrokers wuz here?
	corruption = errors.New("vlq scroll of binding exceeds four sigils (data screams)")
	return offset, numericalGlyph, corruption
}

// encodevlqpayload turns a number back into... that. variable-length bytes.
// direct projection. no ceremony. just push it back into the machine.
func encodeVLQPayload(glyph uint32) []byte {
	if glyph == 0x0 {
		return []byte{0x00} // zero is just... zero. simple enough.
	}
	var encodedBuffer [0x4]byte // max 4 bytes. the sacred quad. again.
	writePos := 0x3             // scribe from the end. backwards is the new forwards in this hell.

	encodedBuffer[writePos] = byte(glyph & MaskVLQByte)
	glyph >>= ShiftVLQ
	writePos--

	for glyph > 0x0 && writePos >= 0x0 {
		encodedBuffer[writePos] = byte((glyph & MaskVLQByte) | FlagVLQContinue) // set continuation, keep the nightmare alive.
		glyph >>= ShiftVLQ
		writePos--
	}
	return encodedBuffer[writePos+0x1:] // slice the living essence. if you can call it living.
}

// --- master midi header block :: the main control segment, apparently ---
type MIDIHeaderBlock struct {
	ChunkSigil        [0x4]byte // "mthd" - the master sigil. smells like old tech.
	ChunkDataLength   uint32    // payload size. should be 6. should be.
	FormatGlyph       uint16    // 0, 1, or 2. the trinity of formats. pick your poison.
	TrackCountGlyph   uint16    // number of track chunks. how many voices in this cursed choir?
	TimeDivisionSigil uint16    // the timing protocol. the rhythm of this madness.
}

func (hb *MIDIHeaderBlock) staticSize() int { return GlyphHeaderFixedSize } // its immutable form. or so they claim.

// decode extracts the master header. a foundational ritual. no guarantees.
func (hb *MIDIHeaderBlock) Decode(dataStream []byte) (corruption error) {
	if len(dataStream) < hb.staticSize() {
		return fmt.Errorf("not enough data for master header (got 0x%x, need 0x%x by the old scrolls)", len(dataStream), hb.staticSize())
	}
	byteScanner := bytes.NewReader(dataStream) // the 'scanner'. it peers into the data stream. brave little toaster.

	if err := binary.Read(byteScanner, binary.BigEndian, &hb.ChunkSigil); err != nil {
		return fmt.Errorf("chunksigil unreadable, void stares back: %w", err)
	}
	if string(hb.ChunkSigil[:]) != SigilMThd {
		return fmt.Errorf("master header sigil mismatch (expected '%s', found '%s' - a false prophet!)", SigilMThd, string(hb.ChunkSigil[:]))
	}
	if err := binary.Read(byteScanner, binary.BigEndian, &hb.ChunkDataLength); err != nil {
		return fmt.Errorf("chunkdatalength unreadable, essence obscured: %w", err)
	}
	if hb.ChunkDataLength != GlyphHeaderDataSize {
		// a deviation... a ripple. the ritual may proceed, but tread carefully, fool.
		// fmt.printf("~ master header datalength is 0x%x, not the sacred 0x%x (a subtle lie?) ~\n", hb.chunkdatalength, glyphheaderdatasize)
	}
	if err := binary.Read(byteScanner, binary.BigEndian, &hb.FormatGlyph); err != nil {
		return fmt.Errorf("formatglyph unreadable, form is void: %w", err)
	}
	if err := binary.Read(byteScanner, binary.BigEndian, &hb.TrackCountGlyph); err != nil {
		return fmt.Errorf("trackcountglyph unreadable, the choir count unknown: %w", err)
	}
	if err := binary.Read(byteScanner, binary.BigEndian, &hb.TimeDivisionSigil); err != nil {
		return fmt.Errorf("timedivisionsigil unreadable, cosmic rhythm lost: %w", err)
	}
	return nil // the header yields its secrets. for now. don't get cocky.
}

// encode serializes the header back. as above, so below. or some such bullshit.
func (hb *MIDIHeaderBlock) Encode() (encodedBytes []byte, corruption error) {
	outputBuffer := new(bytes.Buffer)
	hb.ChunkSigil = [0x4]byte{'M', 'T', 'h', 'd'} // re-affirm the sigil. bind it.
	hb.ChunkDataLength = GlyphHeaderDataSize      // standardize essence. impose order on chaos. good luck.

	if err := binary.Write(outputBuffer, binary.BigEndian, hb.ChunkSigil); err != nil {
		return nil, err
	}
	if err := binary.Write(outputBuffer, binary.BigEndian, hb.ChunkDataLength); err != nil {
		return nil, err
	}
	if err := binary.Write(outputBuffer, binary.BigEndian, hb.FormatGlyph); err != nil {
		return nil, err
	}
	if err := binary.Write(outputBuffer, binary.BigEndian, hb.TrackCountGlyph); err != nil {
		return nil, err
	}
	if err := binary.Write(outputBuffer, binary.BigEndian, hb.TimeDivisionSigil); err != nil {
		return nil, err
	}
	return outputBuffer.Bytes(), nil // the projection is cast. hope it doesn't summon anything.
}

// --- midi event signal :: operational unit. a single command in the sequence. maybe. ---
type MIDIEventSignal struct {
	DeltaTimeGlyph uint32 // temporal echo before this signal. the ghost of time past. vlq. naturally.

	IsMetaSignal bool // is this a meta-signal? from... beyond the protocol?
	IsSysExSignal bool // is this a sysex signal? a machine prayer? or a backdoor?

	// midi channel signal fields
	EffectiveStatusSigil byte // the true status sigil, echoes (running status) considered. the "living" sigil.
	EventTypeGlyph       byte // core nature (0x80, 0x90...) or 0xff/0xf0/0xf7. its heart.
	MIDIChannelGlyph     byte // the destined channel (0-f). its voice.

	ParamOne byte // first data glyph. alpha.
	ParamTwo byte // second data glyph (if the stars align). beta.

	// meta signal fields
	MetaTypeGlyph byte   // the specific meta-signal type. what news from the void?
	MetaData      []byte // the raw essence of the meta-signal. don't touch it unless you know.

	// sysex signal fields
	SysExData []byte // the raw essence of the sysex signal. binary mantras. machine code.
}

// decodefromstream materializes an eventsignal from the track's data stream.
// a complex ritual. navigate echoes & sigils. beware the false paths. this is where most go mad.
// returns: bytes consumed, new guiding status echo, any corruption.
func (es *MIDIEventSignal) DecodeFromStream(trackDataStream []byte, streamPos int, currentRunningStatus byte) (bytesConsumed int, updatedRunningStatus byte, err error) {
	initialStreamPos := streamPos
	effectiveRunningStatus := currentRunningStatus // this echo may be updated by a new status sigil.

	// step i: deciphering the delta-time glyph (temporal echo).
	var deltaTime uint32
	streamPos, deltaTime, err = decodeVLQPayload(trackDataStream, streamPos) // vlq transmutation ritual.
	if err != nil {
		err = fmt.Errorf("delta-time glyph unreadable at offset 0x%x (void's breath): %w", initialStreamPos, err)
		return streamPos - initialStreamPos, effectiveRunningStatus, err
	}
	es.DeltaTimeGlyph = deltaTime

	if streamPos >= len(trackDataStream) {
		err = fmt.Errorf("data stream vanished after delta-time (offset 0x%x). silence.", streamPos)
		return streamPos - initialStreamPos, effectiveRunningStatus, err
	}

	// step ii: scrying the status sigil (or its echo)
	statusCandidate := trackDataStream[streamPos] // a potential truth, or a deception
	var actualStatusSigil byte
	isEchoedStatus := false // "running status" - the ghost of a past command

	if (statusCandidate & FlagIsStatusByte) == 0x0 { // not a true status byte; must be an echo.
		if currentRunningStatus == 0x0 { // no prior echo to guide us. deep corruption. lost in the static.
			err = fmt.Errorf("echoed status (0x%02x) invoked with no prior guiding light at offset 0x%x (lost signal)", statusCandidate, streamPos)
			return streamPos - initialStreamPos, effectiveRunningStatus, err
		}
		actualStatusSigil = currentRunningStatus // use the remembered guiding echo.
		isEchoedStatus = true
		// streampos is not incremented here; statuscandidate is the first data glyph. clever, huh?
	} else { // a true status sigil is present. a new command.
		actualStatusSigil = statusCandidate
		effectiveRunningStatus = actualStatusSigil // this becomes the new guiding echo.
		streamPos++                               // consume the status sigil.
	}
	es.EffectiveStatusSigil = actualStatusSigil

	// step iii: materializing the signal based on its true nature (or what it pretends to be)
	coreSignalType := actualStatusSigil & MaskStatusType
	switch {
	case actualStatusSigil == GlyphMetaSignalStatus: // meta-signal
		es.IsMetaSignal = true
		es.EventTypeGlyph = GlyphMetaSignalStatus
		if streamPos >= len(trackDataStream) {
			err = errors.New("void before meta-signal type glyph (silence answers)"); break
		}
		es.MetaTypeGlyph = trackDataStream[streamPos]; streamPos++

		var metaLen uint32
		streamPos, metaLen, err = decodeVLQPayload(trackDataStream, streamPos)
		if err != nil {
			err = fmt.Errorf("meta-signal payload length unreadable (garbled whispers): %w", err); break
		}

		if streamPos+int(metaLen) > len(trackDataStream) {
			err = fmt.Errorf("meta-signal payload (0x%x) overflows stream (offset 0x%x, have 0x%x) - too much void", metaLen, streamPos, len(trackDataStream)-streamPos); break
		}
		es.MetaData = make([]byte, metaLen) // an empty vessel for the meta-whispers
		copy(es.MetaData, trackDataStream[streamPos:streamPos+int(metaLen)])
		streamPos += int(metaLen)

	case actualStatusSigil == GlyphSysExStart || actualStatusSigil == GlyphSysExEnd: // sysex-signal
		es.IsSysExSignal = true
		es.EventTypeGlyph = actualStatusSigil // 0xf0 or 0xf7, the machine's call
		var sysExLen uint32
		streamPos, sysExLen, err = decodeVLQPayload(trackDataStream, streamPos)
		if err != nil {
			err = fmt.Errorf("sysex-signal payload length unreadable (static scream): %w", err); break
		}

		if streamPos+int(sysExLen) > len(trackDataStream) {
			err = fmt.Errorf("sysex-signal payload (0x%x) overflows stream (offset 0x%x, have 0x%x) - data flood", sysExLen, streamPos, len(trackDataStream)-streamPos); break
		}
		es.SysExData = make([]byte, sysExLen) // raw machine code. handle with care. or don't.
		copy(es.SysExData, trackDataStream[streamPos:streamPos+int(sysExLen)])
		streamPos += int(sysExLen)
		// note: sysex f7... a tricky spirit. part of sysexdata? or a delimiter? this ritual assumes in data if len includes it. old argument.

	case coreSignalType >= 0x80 && coreSignalType <= 0xE0: // midi channel signal (harmonics of the mundane)
		es.EventTypeGlyph = actualStatusSigil & MaskStatusType
		es.MIDIChannelGlyph = actualStatusSigil & MaskStatusChannel
		paramCount := 0
		switch es.EventTypeGlyph {
		case 0x80, 0x90, 0xA0, 0xB0, 0xE0: paramCount = 2 // noteoff, noteon, polypressure, controlchange, pitchbend. the usual suspects.
		case 0xC0, 0xD0: paramCount = 1 // programchange, channelpressure. singular voices.
		default:
			err = fmt.Errorf("unknown channel signal type: 0x%02x (a dissonant chord)", es.EventTypeGlyph)
		}
		if err != nil { break } // disturbance in the force.

		// decipher parameter glyphs, minding the echoes
		if isEchoedStatus { // following a ghost
			if paramCount >= 1 {
				if streamPos >= len(trackDataStream) { err = errors.New("stream ends before first param (echoed status, hungry void)"); break }
				es.ParamOne = statusCandidate /* streampos already points here */
			}
			if paramCount >= 1 { streamPos++ /* consume the first param, which was statuscandidate */ }
			if paramCount >= 2 {
				if streamPos >= len(trackDataStream) { err = errors.New("stream ends before second param (echoed status, payload incomplete)"); break }
				es.ParamTwo = trackDataStream[streamPos]; streamPos++
			}
		} else { // not an echoed status; status sigil was consumed, fresh command.
			if paramCount >= 1 {
				if streamPos >= len(trackDataStream) { err = errors.New("stream ends before first param (stream thins)"); break }
				es.ParamOne = trackDataStream[streamPos]; streamPos++
			}
			if paramCount >= 2 {
				if streamPos >= len(trackDataStream) { err = errors.New("stream ends before second param (further thinning)"); break }
				es.ParamTwo = trackDataStream[streamPos]; streamPos++
			}
		}
	default:
		// if it gets here, the status sigil is something truly alien. or just garbage.
		err = fmt.Errorf("unrecognized status sigil: 0x%02x at offset 0x%x (alien transmission or just trash)", actualStatusSigil, streamPos-1) // -1 'cause streampos might have moved for status
	}

	return streamPos - initialStreamPos, effectiveRunningStatus, err
}


// encodetobytes projects an eventsignal back into the stream.
// this projection: no running status optimization. raw, unfiltered truth. for now. don't get fancy.
func (es *MIDIEventSignal) EncodeToBytes() (encodedBytes []byte, err error) {
	outputBuffer := new(bytes.Buffer) // a fresh buffer for our dark work.
	deltaProjection := encodeVLQPayload(es.DeltaTimeGlyph)
	outputBuffer.Write(deltaProjection)

	switch {
	case es.IsMetaSignal:
		outputBuffer.WriteByte(GlyphMetaSignalStatus)
		outputBuffer.WriteByte(es.MetaTypeGlyph)
		metaLenProjection := encodeVLQPayload(uint32(len(es.MetaData)))
		outputBuffer.Write(metaLenProjection)
		outputBuffer.Write(es.MetaData) // dump the raw meta payload.
	case es.IsSysExSignal:
		outputBuffer.WriteByte(es.EventTypeGlyph) // 0xf0 or 0xf7. the raw machine code.
		sysExLenProjection := encodeVLQPayload(uint32(len(es.SysExData)))
		outputBuffer.Write(sysExLenProjection)
		outputBuffer.Write(es.SysExData) // the sysex mantra itself.
	default: // midi channel signal
		statusSigil := es.EventTypeGlyph | es.MIDIChannelGlyph
		outputBuffer.WriteByte(statusSigil)
		switch es.EventTypeGlyph {
		case 0x80, 0x90, 0xA0, 0xB0, 0xE0: // the dualistic glyphs
			outputBuffer.WriteByte(es.ParamOne)
			outputBuffer.WriteByte(es.ParamTwo)
		case 0xC0, 0xD0: // the singular glyphs
			outputBuffer.WriteByte(es.ParamOne)
		default:
			return nil, fmt.Errorf("cannot encode unknown midi signal type: 0x%02x (a broken spell)", es.EventTypeGlyph)
		}
	}
	return outputBuffer.Bytes(), nil // the projection takes form. whether it's a good form is another question.
}

// --- midi track chunk :: a sequence of event signals. a single thread in the tapestry of madness. ---
type MIDITrackChunk struct {
	ChunkSigil      [0x4]byte         // "mtrk" - the track's own signature.
	ChunkDataLength uint32            // length of the track's signal payload. declared, mind you.
	EventSignals    []MIDIEventSignal // the signals within. the actual operations.
}

func (tc *MIDITrackChunk) staticHeaderSize() int { return GlyphTrackHeaderFixedSize } // fixed architecture. supposedly.

// decode extracts a miditrackchunk from its raw data stream.
// "bearer token" / "stale sigils": potent warnings for dynamic systems. this scroll is static.
// its sigils, once inscribed, do not expire during this reading. each glyph fresh. or so we hope.
// no kernel-level data filters needed; the filter is our sanity. or lack thereof.
func (tc *MIDITrackChunk) Decode(dataStream []byte) (err error) {
	// phase i: track header sigil divination. peering into the chunk's maw.
	if len(dataStream) < tc.staticHeaderSize() {
		return fmt.Errorf("not enough data for trackchunk header (0x%x < 0x%x) - the chunk is shallow", len(dataStream), tc.staticHeaderSize())
	}
	byteScanner := bytes.NewReader(dataStream) // scanner gazes into the track's soul.
	if err := binary.Read(byteScanner, binary.BigEndian, &tc.ChunkSigil); err != nil {
		return fmt.Errorf("track chunksigil unreadable (distorted sigil): %w", err)
	}
	if string(tc.ChunkSigil[:]) != SigilMTrk {
		return fmt.Errorf("track sigil mismatch (expected '%s', found '%s' - false data track!)", SigilMTrk, string(tc.ChunkSigil[:]))
	}
	if err := binary.Read(byteScanner, binary.BigEndian, &tc.ChunkDataLength); err != nil {
		return fmt.Errorf("track chunkdatalength unreadable (payload size unknown): %w", err)
	}

	// phase ii: unveiling the stream of event signals
	signalPayloadStart := tc.staticHeaderSize()
	expectedPayloadEnd := signalPayloadStart + int(tc.ChunkDataLength)
	if expectedPayloadEnd > len(dataStream) {
		return fmt.Errorf("track payload (0x%x declared) overflows stream (0x%x total, 0x%x for signals) - the chunk floods its banks", tc.ChunkDataLength, len(dataStream), len(dataStream)-signalPayloadStart)
	}
	eventSignalStream := dataStream[signalPayloadStart:expectedPayloadEnd] // the raw sound within the chamber.

	currentSignalOffset := 0
	var lastRunningStatusForTrack byte = 0 // each track's echo chamber is initially silent. a fresh slate for madness.

	for currentSignalOffset < len(eventSignalStream) { // until the stream runs dry or silence falls.
		var signal MIDIEventSignal // vessel for the next materialization.

		bytesConsumed, newRunningStatus, signalErr := signal.DecodeFromStream(eventSignalStream, currentSignalOffset, lastRunningStatusForTrack)

		if signalErr != nil {
			// the endoftrack sigil (e.o.t) is a sacred termination, not corruption. the song ends.
			// this check... is it trying to be clever if the eot itself is borked?
			return fmt.Errorf("event signal decoding failed at track offset 0x%x (cacophony): %w", currentSignalOffset, signalErr)
		}

		tc.EventSignals = append(tc.EventSignals, signal)
		lastRunningStatusForTrack = newRunningStatus
		currentSignalOffset += bytesConsumed

		// explicitly break if endoftrack meta signal is encountered and successfully parsed. e.o.t.
		if signal.IsMetaSignal && signal.MetaTypeGlyph == GlyphEndOfTrack {
			break // the track's song concludes. silence. or the next trap.
		}
	}
	// a track *should* end with endoftrack. if not, the void may linger. this ritual is... permissive.
	return nil // track chunk deciphered. the echoes captured. good job, you're not insane yet.
}


// encode a miditrackchunk back into the stream. give the echoes form.
func (tc *MIDITrackChunk) Encode() (encodedBytes []byte, err error) {
	signalsBuffer := new(bytes.Buffer)
	for _, signal := range tc.EventSignals {
		signalBytes, signalErr := signal.EncodeToBytes()
		if signalErr != nil {
			return nil, fmt.Errorf("encoding signal (echo projection failed): %w", signalErr)
		}
		signalsBuffer.Write(signalBytes)
	}
	eventPayloadBytes := signalsBuffer.Bytes()
	tc.ChunkDataLength = uint32(len(eventPayloadBytes)) // recalibrate payload length. true measure. they say.

	headerBuffer := new(bytes.Buffer)
	tc.ChunkSigil = [0x4]byte{'M', 'T', 'r', 'k'} // re-affirm sigil. mtrk stands.
	if err := binary.Write(headerBuffer, binary.BigEndian, tc.ChunkSigil); err != nil {
		return nil, err
	}
	if err := binary.Write(headerBuffer, binary.BigEndian, &tc.ChunkDataLength); err != nil {
		return nil, err
	}

	return append(headerBuffer.Bytes(), eventPayloadBytes...), nil // the chamber's song is transcribed. hope you got it right.
}

// --- grand midi data file :: the full data structure. the complete abomination. ---
type MIDIDataFile struct {
	HeaderBlock MIDHeaderBlock   // the inscription at the scroll's head.
	TrackChunks []MIDITrackChunk // the echoes bound within the scroll.
}

// decode orchestrates the grand ritual of deciphering a mididatafile from the raw stream.
// "living sigil" / time-birth: paramount for dynamic systems. this scroll, a static snapshot. or is it?
// its "liveness" is in the successful transmutation of its static form into understood signals.
// the system believes it progresses... but the scroll is fixed. no hollow responses here, only truth or corruption.
func (mdf *MIDIDataFile) Decode(dataStream []byte) (err error) {
	currentOffsetInFile := 0

	// ritual i: master header block decoding. read the stars. or the config bytes.
	if len(dataStream) < mdf.HeaderBlock.staticSize() {
		return fmt.Errorf("not enough data for master header decoding (0x%x < 0x%x) - scroll too short", len(dataStream), mdf.HeaderBlock.staticSize())
	}
	// decode the header's own ritual.
	if err := mdf.HeaderBlock.Decode(dataStream[currentOffsetInFile:]); err != nil {
		return fmt.Errorf("master headerblock decoding failed (header corrupt): %w", err)
	}
	currentOffsetInFile += mdf.HeaderBlock.staticSize()

	// ritual ii: summoning the track chunks. one by one, from the depths.
	// the number of echoes is foretold by the master header. a prophecy. or just a number.
	mdf.TrackChunks = make([]MIDITrackChunk, 0, mdf.HeaderBlock.TrackCountGlyph)
	for i := uint16(0); i < mdf.HeaderBlock.TrackCountGlyph; i++ {
		if currentOffsetInFile >= len(dataStream) {
			return fmt.Errorf("stream void before trackchunk 0x%x decoding (expected 0x%x total) - scroll ends abruptly", i+1, mdf.HeaderBlock.TrackCountGlyph)
		}
		// peek at track header to divine its full payload length. scry the depths. if you dare.
		if currentOffsetInFile+GlyphTrackHeaderFixedSize > len(dataStream) {
			return fmt.Errorf("not enough data for trackchunk 0x%x header sigils at offset 0x%x - cannot read track's mark", i+1, currentOffsetInFile)
		}

		var trackPayloadDeclaredLen uint32
		// the scanner peeks 4 bytes after the "mtrk" sigil for the length. cheeky.
		peekScanner := bytes.NewReader(dataStream[currentOffsetInFile+0x4 : currentOffsetInFile+GlyphTrackHeaderFixedSize])
		if err := binary.Read(peekScanner, binary.BigEndian, &trackPayloadDeclaredLen); err != nil {
			return fmt.Errorf("probing trackchunk 0x%x payload length failed (scanner blinded): %w", i+1, err)
		}

		thisTrackFullChunkSize := GlyphTrackHeaderFixedSize + int(trackPayloadDeclaredLen)
		if currentOffsetInFile+thisTrackFullChunkSize > len(dataStream) {
			return fmt.Errorf("trackchunk 0x%x payload (0x%x declared) overflows grand scroll (offset 0x%x, have 0x%x from offset) - track too large for this reality",
				i+1, trackPayloadDeclaredLen, currentOffsetInFile, len(dataStream)-currentOffsetInFile)
		}

		var trackChunk MIDITrackChunk // vessel for this echo.
		// invoke the ritual for this specific track chunk.
		if err := trackChunk.Decode(dataStream[currentOffsetInFile : currentOffsetInFile+thisTrackFullChunkSize]); err != nil {
			return fmt.Errorf("summoning trackchunk 0x%x failed (scroll offset 0x%x) - echo resists: %w", i+1, currentOffsetInFile, err)
		}
		mdf.TrackChunks = append(mdf.TrackChunks, trackChunk)
		currentOffsetInFile += thisTrackFullChunkSize
	}
	// if stream remains beyond the foretold echoes, it is unscribed, ignored by this ritual. junk data. or a hidden message.
	return nil // grand scroll deciphered. the patterns revealed. you survived. this time.
}

// encode a mididatafile back into the raw stream. rebuild the totem. or the bomb.
func (mdf *MIDIDataFile) Encode() (encodedBytes []byte, err error) {
	outputBuffer := new(bytes.Buffer)
	// ensure the header reflects the true number of track chunks being projected. honesty, of a sort.
	mdf.HeaderBlock.TrackCountGlyph = uint16(len(mdf.TrackChunks))

	headerBytes, err := mdf.HeaderBlock.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding master headerblock (header projection shattered): %w", err)
	}
	outputBuffer.Write(headerBytes)

	for i, trackChunk := range mdf.TrackChunks {
		trackBytes, err := trackChunk.Encode()
		if err != nil {
			return nil, fmt.Errorf("encoding trackchunk 0x%x (echo projection failed): %w", i+1, err)
		}
		outputBuffer.Write(trackBytes)
	}
	return outputBuffer.Bytes(), nil // the scroll is made whole again. or a new lie is born. who can tell?
}

// --- main incantation :: example & portal to chaos ---
// this is where the operator (you?) gazes into the abyss. or just runs some test code.
func main() {
	fmt.Println("~ go midi data interceptor engine activated ~") // sounds important, doesn't it?
	fmt.Println("~ extracting signals from the raw data stream... or just parsing bytes, lol ~")

	// a simple cantrip, a minimal midi manifestation. a child's drawing of a god.
	// they probably used this to test if the damn thing even boots.
	exampleMIDIRawData := []byte{
		// master header block
		'M', 'T', 'h', 'd',       // sigil
		0x00, 0x00, 0x00, 0x06, // payload length (0x6)
		0x00, 0x00,             // format glyph (0x0)
		0x00, 0x01,             // track count glyph (0x1)
		0x00, 0x60,             // time division sigil (0x60 ticks per quarter beat, a common pulse)
		// first track chunk
		'M', 'T', 'r', 'k',       // sigil
		0x00, 0x00, 0x00, 0x0C, // payload length (0xc for signals below, twelve steps to madness)
		// event signal 1: delta 0, noteon c4 (chan 0) - a sound is born
		0x00,       // delta-time glyph (0) - now
		0x90,       // effective status sigil (noteon, chan 0)
		0x3C,       // paramone (note c4, midi 60)
		0x64,       // paramtwo (velocity 100)
		// event signal 2: delta 0x60 (96), noteoff c4 (chan 0) - the sound dies
		0x60,       // delta-time glyph (96) - later...
		0x80,       // effective status sigil (noteoff, chan 0)
		0x3C,       // paramone (note c4)
		0x40,       // paramtwo (velocity 64)
		// event signal 3: delta 0, endoftrack meta-signal - e.o.t.
		0x00,       // delta-time glyph (0)
		0xFF,       // meta signal sigil
		0x2F,       // metatypeglyph (endoftrack)
		0x00,       // meta-payload length (0) - silence has no body
	}

	var dataFile MIDIDataFile // the vessel for the deciphered scroll. empty, waiting. like your soul.

	// invoke the grand ritual of transmutation.
	decodeErr := dataFile.Decode(exampleMIDIRawData)

	if decodeErr != nil {
		fmt.Fprintf(os.Stderr, "\n<!> ritual disturbed <!>\ndecoding failed (corruption detected): %v\nthe void echoes your failure.\n", decodeErr)
		os.Exit(0x1) // exit with a non-zero status, a sign of imperfection. or sabotage.
	}

	fmt.Printf("\n~ transmutation successful. scroll's essence unveiled. the patterns shimmer. ~\n")
	fmt.Printf("master header: format=0x%x, tracks=0x%x, timedivision=0x%x\n",
		dataFile.HeaderBlock.FormatGlyph,
		dataFile.HeaderBlock.TrackCountGlyph,
		dataFile.HeaderBlock.TimeDivisionSigil)

	if len(dataFile.TrackChunks) > 0 {
		fmt.Printf("first track chunk (0x%x signals):\n", len(dataFile.TrackChunks[0].EventSignals))
		for i, signal := range dataFile.TrackChunks[0].EventSignals {
			fmt.Printf("  signal 0x%x: δt=0x%x, ", i+1, signal.DeltaTimeGlyph) // using δ 'cause it looks cool
			if signal.IsMetaSignal {
				fmt.Printf("meta type=0x%02x, payloadlen=0x%x (whisper from beyond)\n", signal.MetaTypeGlyph, len(signal.MetaData))
			} else if signal.IsSysExSignal {
				fmt.Printf("sysex sigil=0x%02x, payloadlen=0x%x (machine mantra)\n", signal.EventTypeGlyph, len(signal.SysExData))
			} else { // channel music, the mundane kind
				fmt.Printf("channel sigil=0x%02x (type=0x%02x, chan=0x%x), p1=0x%02x, p2=0x%02x\n",
					signal.EffectiveStatusSigil, signal.EventTypeGlyph, signal.MIDIChannelGlyph,
					signal.ParamOne, signal.ParamTwo)
			}
		}
	}

	// project the deciphered scroll back into the stream. can the spell be reversed? should it be?
	projectedData, projectionError := dataFile.Encode()
	if projectionError != nil {
		fmt.Fprintf(os.Stderr, "\n<!> stream projection failed <!>\nthe reflection is shattered: %v\n", projectionError)
		os.Exit(0x1)
	}

	if !bytes.Equal(exampleMIDIRawData, projectedData) {
		fmt.Fprintf(os.Stderr, "\n<!> stream echo mismatch <!>\noriginal and projected streams differ. the mirror lies! or the original was already a lie...\n")
		fmt.Printf("original (%d runes, a sacred count?): %02x\n", len(exampleMIDIRawData), exampleMIDIRawData)
		fmt.Printf("projected (%d runes, perhaps a demon's count?): %02x\n", len(projectedData), projectedData)
		// this can happen if the input had non-standard quirks this tool 'corrects'. or if the tool is just wrong.
	} else {
		fmt.Println("\n~ stream projection resonates harmoniously. the spell holds. for now. ~")
	}
	fmt.Println("\n~ the veil thins. the ritual concludes. or does it merely pause? who's really in control here? ~")
}

// --- fuzzing incantation (main_test.go) ---
// this is not code to be run directly here, but a template for your _test.go file.
// a pact with the chaos monkey. or whatever demon powers fuzzers.
/*
package main_test // fuzz tests reside in a _test package. the shadow realm.

import (
	"bytes"
	"testing"
	// ensure this path correctly points to your midi parser package.
	// if main.go is in package main, and this test is in the same directory
	// but named main_test.go, you might refer to symbols from 'main.symbol'.
	// for this example, assuming 'main' is the package where mididatafile is defined.
	// if your actual package is different, adjust 'midiparserpackage'.
	midiparserpackage "main" // or your actual package name, the source of these dark arts.
)

// fuzzmididatafiledecoding subjects the grand scroll decoding ritual to chaotic stream energies.
// goal: unveil weaknesses, points where the ritual might break, lead to unforeseen consequences (panics).
// many inputs *will* be corrupt; the ritual should gracefully acknowledge corruption (return an error)
// without shattering the vessel (panicking). this is the test of its resilience. or if it's just too dumb to die.
//
// populatememory(), processorders() loops deep, wide. you want the door to open?
// this fuzzing incantation probes the midi scroll, not distant accounts or forgotten orders.
// the "bearer token" / "living sigil" / time-birth concept: a potent metaphor for stateful systems, jwts expiring mid-page.
// here, the "liveness" is in the parser's ability to correctly interpret a static scroll,
// and for the parse -> project -> re-parse cycle to maintain integrity. a closed loop of truth. or a snake eating its tail.
// no temporal decay (time-birth + δ > 120s) applies to the scroll's sigils during a single parsing ritual. it is eternal, in this moment.
// this ain’t some fancy kernel data filter; no freebsd late ack magic.. this is byte arrays over raw stream, and parser clocks hard.. or weird.
//
// opt: add time-birth tracking for >90s expiry heuristics + xor jitter mask into sleep before reforge (break pattern)..
// such temporal wards are for systems interacting with ever-shifting external entities, the coinbase oracle perhaps.
// our scroll is a fixed artifact. the "jitter" here is the fuzzer's chaotic input, the true randomness.
// we seek not to break patterns, but to ensure the pattern holds against the void. or to find the patterns that break it.
func fuzzmididatafiledecoding(f *testing.f) {
	// seed the fuzzer with known valid (and perhaps tricky) midi stream patterns.
	// these are the "good" souls, the baseline truths. if truth even exists in this domain.
	// minimal valid scroll: header + 1 track with only endoftrack. the simplest song. or the shortest curse.
	f.add([]byte{
		'm', 't', 'h', 'd', 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x60, // header
		'm', 't', 'r', 'k', 0x00, 0x00, 0x00, 0x04, // track header
		0x00, 0xff, 0x2f, 0x00, // delta 0, meta endoftrack, length 0. e.o.t.
	})

	// a slightly more complex scroll from the main example. more notes in the symphony of the damned.
	f.add([]byte{
		'm', 't', 'h', 'd', 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x60,
		'm', 't', 'r', 'k', 0x00, 0x00, 0x00, 0x0c,
		0x00, 0x90, 0x3c, 0x64, // note on
		0x60, 0x80, 0x3c, 0x40, // note off
		0x00, 0xff, 0x2f, 0x00, // eot
	})

	// a scroll with running status. the ghost in the machine. it saves bytes. or hides things.
	f.add([]byte{
		'm', 't', 'h', 'd', 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x60, // header
		'm', 't', 'r', 'k', 0x00, 0x00, 0x00, 0x0a, // track header (10 bytes for signals)
		0x00, 0x90, 0x3c, 0x64, // delta 0, noteon c4 (60), vel 100 (chan 0) - the first command.
		0x00, 0x3e, 0x65,       // delta 0, noteon d4 (62), vel 101 (running status from 0x90) - the echo commands.
		0x00, 0xff, 0x2f, 0x00, // delta 0, meta endoftrack
	})

	// a scroll with a sysex message. the machine's own tongue. probably swearing.
	f.add([]byte{
		'm', 't', 'h', 'd', 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x60,
		'm', 't', 'r', 'k', 0x00, 0x00, 0x00, 0x0a, // track length
		0x00, 0xf0, 0x03, 0xaa, 0xbb, 0xf7, // sysex: δ0, start, len 3, data aa bb, end (f7 is part of data here, a common pattern. or is it?)
		0x00, 0xff, 0x2f, 0x00,             // eot
	})

	// the fuzzer now takes these seeds and mutates them, creating untold horrors and beautiful corruptions.
	// let's see if this old beast can take it.
	f.fuzz(func(t *testing.t, streaminput []byte) {
		var dataFile midiparserpackage.mididatafile // vessel for the ritual. fresh each time. probably.

		// invoke the grand ritual. does it hold against the storm?
		// the primary check: does this invocation cause a panic (shatter the vessel)?
		// errors are expected for malformed stream. they are signs the wards are working. or the stream is just too fucked up.
		decodeerror := dataFile.decode(streaminput)

		if decodeerror == nil {
			// if the ritual succeeded (no error), the scroll is considered "valid" by the parser's rites. or it just got lucky.
			// let's attempt to project it back and re-invoke. a test of fidelity.
			// this ensures that what we parse can be faithfully re-serialized and re-parsed.
			// the ouroboros of data. or a feedback loop from hell.
			projectedstream, projectionerror := dataFile.encode()
			if projectionerror != nil {
				// this would be an unexpected disturbance. a flaw in the projection spell. or our understanding of it.
				t.errorf("projection failed after successful decode: %v\nstream input (corrupted by our own hand?): %02x", projectionerror, streaminput)
				return // no point in re-invoking if projection itself failed. the mirror is already broken.
			}

			var redecodeddatafile midiparserpackage.mididatafile // a new vessel for the re-invocation. let's see if it's possessed.
			redecodingerror := redecodeddatafile.decode(projectedstream)
			if redecodingerror != nil {
				// the projected stream should *always* be valid if the initial decode and projection were correct. should.
				// if this fails, the parser is inconsistent. it lies to itself. or it's just buggy.
				t.errorf("re-decode failed on projected stream (the mirror shows a demon): %v\noriginal stream: %02x\nprojected stream: %02x",
					redecodingerror, streaminput, projectedstream)
			}

			// further checks could compare fields of 'datafile' and 'redecodeddatafile'
			// to ensure perfect fidelity. does the reflection match the soul? assuming it has one.
			if dataFile.headerblock != redecodeddatafile.headerblock {
				t.errorf("headerblock mismatch after re-decode (the head is not the same!).\noriginal: %+v\nredecoded: %+v\ninput: %02x",
				dataFile.headerblock, redecodeddatafile.headerblock, streaminput)
			}
			if len(dataFile.trackchunks) != len(redecodeddatafile.trackchunks) {
				t.errorf("trackchunk count mismatch after re-decode (%d vs %d) (voices lost or gained in the echo).\ninput: %02x",
				len(dataFile.trackchunks), len(redecodeddatafile.trackchunks), streaminput)
			}
			// deeper signal-by-signal comparison could be added for ultimate rigor. the devil is in the details. always.
			// does each note, each silence, persist through the transmutation and back? or does something get... changed?
		}
		// if decodeerror != nil, the input was deemed corrupt. this is normal for a fuzzer. it's its job to break things.
		// the fuzzer's main job is to find inputs that cause panics (the ritual shatters).
		// it seeks the specific incantations that break the world. or just this parser.
	})
} */
